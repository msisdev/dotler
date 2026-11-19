//! Pure-Rust client for the freedesktop.org D-Bus Secret Service (`org.freedesktop.secrets`).
//!
//! Communicates directly over the session D-Bus Unix domain socket using the standard binary
//! wire protocol and `plain` session transport, requiring zero external CLI utilities or C
//! shared libraries.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroize;

use crate::crypto::keyring::{KEYRING_DEFAULT_USER, KEYRING_SERVICE_NAME, KeyringError};

pub const DBUS_IO_TIMEOUT: Duration = Duration::from_secs(2);
const DBUS_PROMPT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADER_FIELDS_LEN: usize = 1_048_576;
const MAX_BODY_LEN: usize = 4_194_304;
const MAX_SASL_LINE_LEN: usize = 512;

const DBUS_BUS_DEST: &str = "org.freedesktop.DBus";
const DBUS_BUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_BUS_IFACE: &str = "org.freedesktop.DBus";

pub const SECRET_SERVICE_DEST: &str = "org.freedesktop.secrets";
const SECRET_SERVICE_PATH: &str = "/org/freedesktop/secrets";
const DEFAULT_COLLECTION_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const SESSION_IFACE: &str = "org.freedesktop.Secret.Session";
const PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";

pub const GENERIC_SCHEMA_VALUE: &str = "org.freedesktop.Secret.Generic";

const MSG_METHOD_CALL: u8 = 1;
const MSG_METHOD_RETURN: u8 = 2;
const MSG_ERROR: u8 = 3;
const MSG_SIGNAL: u8 = 4;

const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SIGNATURE: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn from_byte(b: u8) -> Result<Self, KeyringError> {
        match b {
            b'l' => Ok(Self::Little),
            b'B' => Ok(Self::Big),
            other => Err(KeyringError::BackendError(format!(
                "Unsupported D-Bus endianness byte: {other}"
            ))),
        }
    }

    fn read_u16(self, bytes: &[u8]) -> u16 {
        let arr = [bytes[0], bytes[1]];
        match self {
            Self::Little => u16::from_le_bytes(arr),
            Self::Big => u16::from_be_bytes(arr),
        }
    }

    fn read_u32(self, bytes: &[u8]) -> u32 {
        let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Little => u32::from_le_bytes(arr),
            Self::Big => u32::from_be_bytes(arr),
        }
    }
}

struct DbusMessage {
    endian: Endian,
    msg_type: u8,
    reply_serial: Option<u32>,
    path: Option<String>,
    interface: Option<String>,
    member: Option<String>,
    error_name: Option<String>,
    signature: Option<String>,
    body: Vec<u8>,
}

impl Drop for DbusMessage {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

struct DbusWriter {
    buf: Vec<u8>,
}

impl Drop for DbusWriter {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl DbusWriter {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    fn pad_to(&mut self, align: usize) {
        if align <= 1 {
            return;
        }
        let rem = self.buf.len() % align;
        if rem != 0 {
            self.buf.resize(self.buf.len() + (align - rem), 0);
        }
    }

    fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    fn write_bool(&mut self, val: bool) {
        self.write_u32(u32::from(val));
    }

    fn write_u32(&mut self, val: u32) {
        self.pad_to(4);
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    fn write_str(&mut self, val: &str) {
        self.write_u32(val.len() as u32);
        self.buf.extend_from_slice(val.as_bytes());
        self.buf.push(0);
    }

    fn write_sig(&mut self, sig: &str) {
        self.buf.push(sig.len() as u8);
        self.buf.extend_from_slice(sig.as_bytes());
        self.buf.push(0);
    }

    fn write_byte_array(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    fn write_array(&mut self, elem_align: usize, f: impl FnOnce(&mut Self)) {
        self.pad_to(4);
        let len_pos = self.buf.len();
        self.buf.extend_from_slice(&0u32.to_le_bytes());
        self.pad_to(elem_align);
        let start = self.buf.len();
        f(self);
        let byte_len = (self.buf.len() - start) as u32;
        self.buf[len_pos..len_pos + 4].copy_from_slice(&byte_len.to_le_bytes());
    }

    fn write_dict_ss(&mut self, entries: &[(&str, &str)]) {
        self.write_array(8, |w| {
            for (k, v) in entries {
                w.pad_to(8);
                w.write_str(k);
                w.write_str(v);
            }
        });
    }
}

struct DbusReader<'a> {
    buf: &'a [u8],
    pos: usize,
    endian: Endian,
}

impl<'a> DbusReader<'a> {
    fn new(buf: &'a [u8], endian: Endian) -> Self {
        Self {
            buf,
            pos: 0,
            endian,
        }
    }

    fn align_to(&mut self, align: usize) -> Result<(), KeyringError> {
        if align <= 1 {
            return Ok(());
        }
        let rem = self.pos % align;
        if rem != 0 {
            let next = self.pos + (align - rem);
            if next > self.buf.len() {
                return Err(KeyringError::BackendError(
                    "Truncated D-Bus alignment padding".to_string(),
                ));
            }
            self.pos = next;
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], KeyringError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| KeyringError::BackendError("D-Bus length overflow".to_string()))?;
        if end > self.buf.len() {
            return Err(KeyringError::BackendError(
                "Truncated D-Bus payload".to_string(),
            ));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, KeyringError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, KeyringError> {
        self.align_to(2)?;
        Ok(self.endian.read_u16(self.take(2)?))
    }

    fn read_u32(&mut self) -> Result<u32, KeyringError> {
        self.align_to(4)?;
        Ok(self.endian.read_u32(self.take(4)?))
    }

    fn read_bool(&mut self) -> Result<bool, KeyringError> {
        Ok(self.read_u32()? != 0)
    }

    fn read_str(&mut self) -> Result<&'a str, KeyringError> {
        let len = self.read_u32()? as usize;
        let bytes = self.take(len)?;
        let nul = self.read_u8()?;
        if nul != 0 {
            return Err(KeyringError::BackendError(
                "Missing NUL terminator in D-Bus string".to_string(),
            ));
        }
        std::str::from_utf8(bytes)
            .map_err(|e| KeyringError::BackendError(format!("Invalid UTF-8 in D-Bus string: {e}")))
    }

    fn read_sig(&mut self) -> Result<&'a str, KeyringError> {
        let len = self.read_u8()? as usize;
        let bytes = self.take(len)?;
        let nul = self.read_u8()?;
        if nul != 0 {
            return Err(KeyringError::BackendError(
                "Missing NUL terminator in D-Bus signature".to_string(),
            ));
        }
        std::str::from_utf8(bytes).map_err(|e| {
            KeyringError::BackendError(format!("Invalid UTF-8 in D-Bus signature: {e}"))
        })
    }

    fn read_byte_array(&mut self) -> Result<&'a [u8], KeyringError> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }

    fn read_object_path_array(&mut self) -> Result<Vec<String>, KeyringError> {
        let byte_len = self.read_u32()? as usize;
        self.align_to(4)?;
        let end = self
            .pos
            .checked_add(byte_len)
            .ok_or_else(|| KeyringError::BackendError("D-Bus array overflow".to_string()))?;
        if end > self.buf.len() {
            return Err(KeyringError::BackendError(
                "Truncated D-Bus object path array".to_string(),
            ));
        }
        let mut out = Vec::new();
        while self.pos < end {
            out.push(self.read_str()?.to_string());
        }
        Ok(out)
    }

    fn skip_signature(&mut self, sig: &str) -> Result<(), KeyringError> {
        let mut rest = sig;
        while !rest.is_empty() {
            rest = self.skip_one_type(rest)?;
        }
        Ok(())
    }

    fn skip_one_type<'s>(&mut self, sig: &'s str) -> Result<&'s str, KeyringError> {
        let first = sig.as_bytes()[0];
        match first {
            b'y' => {
                let _ = self.read_u8()?;
                Ok(&sig[1..])
            }
            b'n' | b'q' => {
                let _ = self.read_u16()?;
                Ok(&sig[1..])
            }
            b'b' | b'i' | b'u' | b'h' => {
                let _ = self.read_u32()?;
                Ok(&sig[1..])
            }
            b'x' | b't' | b'd' => {
                self.align_to(8)?;
                let _ = self.take(8)?;
                Ok(&sig[1..])
            }
            b's' | b'o' => {
                let _ = self.read_str()?;
                Ok(&sig[1..])
            }
            b'g' => {
                let _ = self.read_sig()?;
                Ok(&sig[1..])
            }
            b'v' => {
                let inner_sig = self.read_sig()?.to_string();
                self.skip_signature(&inner_sig)?;
                Ok(&sig[1..])
            }
            b'a' => {
                let after_elem = split_one_complete_type(&sig[1..])?;
                let elem_sig = &sig[1..sig.len() - after_elem.len()];
                let elem_align = type_alignment(elem_sig)?;
                let byte_len = self.read_u32()? as usize;
                self.align_to(elem_align)?;
                let _ = self.take(byte_len)?;
                Ok(after_elem)
            }
            b'(' => {
                let after_struct = split_one_complete_type(sig)?;
                let inner = &sig[1..sig.len() - after_struct.len() - 1];
                self.align_to(8)?;
                self.skip_signature(inner)?;
                Ok(after_struct)
            }
            b'{' => {
                let after_entry = split_one_complete_type(sig)?;
                let inner = &sig[1..sig.len() - after_entry.len() - 1];
                self.align_to(8)?;
                self.skip_signature(inner)?;
                Ok(after_entry)
            }
            other => Err(KeyringError::BackendError(format!(
                "Unsupported D-Bus type signature byte: {other}"
            ))),
        }
    }
}

fn type_alignment(sig: &str) -> Result<usize, KeyringError> {
    let Some(&first) = sig.as_bytes().first() else {
        return Err(KeyringError::BackendError(
            "Empty D-Bus type signature".to_string(),
        ));
    };
    match first {
        b'y' | b'g' | b'v' => Ok(1),
        b'n' | b'q' => Ok(2),
        b'b' | b'i' | b'u' | b'h' | b's' | b'o' | b'a' => Ok(4),
        b'x' | b't' | b'd' | b'(' | b'{' => Ok(8),
        other => Err(KeyringError::BackendError(format!(
            "Unknown D-Bus alignment for signature byte: {other}"
        ))),
    }
}

fn split_one_complete_type(sig: &str) -> Result<&str, KeyringError> {
    let bytes = sig.as_bytes();
    let Some(&first) = bytes.first() else {
        return Err(KeyringError::BackendError(
            "Unexpected end of D-Bus signature".to_string(),
        ));
    };
    match first {
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b'h' | b's' | b'o'
        | b'g' | b'v' => Ok(&sig[1..]),
        b'a' => split_one_complete_type(&sig[1..]),
        b'(' => find_matching_delim(sig, b'(', b')'),
        b'{' => find_matching_delim(sig, b'{', b'}'),
        other => Err(KeyringError::BackendError(format!(
            "Invalid D-Bus signature token: {other}"
        ))),
    }
}

fn find_matching_delim(sig: &str, open: u8, close: u8) -> Result<&str, KeyringError> {
    let mut depth = 0usize;
    for (idx, &b) in sig.as_bytes().iter().enumerate() {
        if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return Ok(&sig[idx + 1..]);
            }
        }
    }
    Err(KeyringError::BackendError(format!(
        "Unbalanced D-Bus container signature: {sig}"
    )))
}

struct DbusClient {
    stream: UnixStream,
    next_serial: u32,
    allow_gui_prompt: bool,
}

impl DbusClient {
    fn connect() -> Result<Self, KeyringError> {
        let stream = connect_session_bus()?;
        let allow_gui_prompt =
            std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
        Self::from_stream(stream, allow_gui_prompt)
    }

    fn from_stream(stream: UnixStream, allow_gui_prompt: bool) -> Result<Self, KeyringError> {
        stream
            .set_read_timeout(Some(DBUS_IO_TIMEOUT))
            .map_err(|e| KeyringError::BackendError(format!("Failed to set D-Bus timeout: {e}")))?;
        stream
            .set_write_timeout(Some(DBUS_IO_TIMEOUT))
            .map_err(|e| KeyringError::BackendError(format!("Failed to set D-Bus timeout: {e}")))?;

        let mut client = Self {
            stream,
            next_serial: 1,
            allow_gui_prompt,
        };
        client.sasl_authenticate()?;
        let _ = client.call(
            DBUS_BUS_DEST,
            DBUS_BUS_PATH,
            DBUS_BUS_IFACE,
            "Hello",
            "",
            |_| {},
        )?;
        Ok(client)
    }

    fn sasl_authenticate(&mut self) -> Result<(), KeyringError> {
        self.stream
            .write_all(&[0u8])
            .map_err(|e| KeyringError::BackendError(format!("D-Bus SASL write failed: {e}")))?;

        let auth_cmd = match effective_uid_hex() {
            Some(hex_uid) => format!("AUTH EXTERNAL {hex_uid}\r\n"),
            None => "AUTH EXTERNAL\r\n".to_string(),
        };
        self.stream
            .write_all(auth_cmd.as_bytes())
            .map_err(|e| KeyringError::BackendError(format!("D-Bus AUTH write failed: {e}")))?;

        let mut line = self.read_sasl_line()?;
        if line.starts_with("DATA") {
            self.stream
                .write_all(b"DATA\r\n")
                .map_err(|e| KeyringError::BackendError(format!("D-Bus DATA write failed: {e}")))?;
            line = self.read_sasl_line()?;
        }

        if !line.starts_with("OK ") {
            return Err(KeyringError::BackendError(format!(
                "D-Bus SASL authentication failed: {line}"
            )));
        }

        self.stream
            .write_all(b"BEGIN\r\n")
            .map_err(|e| KeyringError::BackendError(format!("D-Bus BEGIN write failed: {e}")))?;
        Ok(())
    }

    fn read_sasl_line(&mut self) -> Result<String, KeyringError> {
        let mut bytes = Vec::with_capacity(64);
        let mut byte = [0u8; 1];
        while bytes.len() < MAX_SASL_LINE_LEN {
            self.stream
                .read_exact(&mut byte)
                .map_err(|e| KeyringError::BackendError(format!("D-Bus SASL read failed: {e}")))?;
            bytes.push(byte[0]);
            if bytes.ends_with(b"\r\n") {
                bytes.truncate(bytes.len() - 2);
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        Err(KeyringError::BackendError(
            "D-Bus SASL response line exceeded maximum length".to_string(),
        ))
    }

    fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        signature: &str,
        write_body: impl FnOnce(&mut DbusWriter),
    ) -> Result<DbusMessage, KeyringError> {
        let serial = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1).max(1);

        let mut body = DbusWriter::new();
        write_body(&mut body);

        let mut frame = DbusWriter::new();
        frame.buf.extend_from_slice(&[b'l', MSG_METHOD_CALL, 0, 1]);
        frame.write_u32(body.buf.len() as u32);
        frame.write_u32(serial);

        frame.write_array(8, |hdr| {
            hdr.pad_to(8);
            hdr.write_u8(FIELD_PATH);
            hdr.write_sig("o");
            hdr.write_str(path);

            hdr.pad_to(8);
            hdr.write_u8(FIELD_INTERFACE);
            hdr.write_sig("s");
            hdr.write_str(interface);

            hdr.pad_to(8);
            hdr.write_u8(FIELD_MEMBER);
            hdr.write_sig("s");
            hdr.write_str(member);

            hdr.pad_to(8);
            hdr.write_u8(FIELD_DESTINATION);
            hdr.write_sig("s");
            hdr.write_str(destination);

            if !signature.is_empty() {
                hdr.pad_to(8);
                hdr.write_u8(FIELD_SIGNATURE);
                hdr.write_sig("g");
                hdr.write_sig(signature);
            }
        });
        frame.pad_to(8);
        frame.buf.extend_from_slice(&body.buf);

        self.stream
            .write_all(&frame.buf)
            .map_err(|e| KeyringError::BackendError(format!("D-Bus write failed: {e}")))?;

        loop {
            let msg = self.read_message()?;
            match msg.msg_type {
                MSG_METHOD_RETURN if msg.reply_serial == Some(serial) => return Ok(msg),
                MSG_ERROR if msg.reply_serial == Some(serial) => {
                    let err_name = msg
                        .error_name
                        .as_deref()
                        .unwrap_or("org.freedesktop.DBus.Error.Failed");
                    let detail = if msg.signature.as_deref().is_some_and(|s| s.starts_with('s')) {
                        let mut r = DbusReader::new(&msg.body, msg.endian);
                        r.read_str().ok().map(str::to_string)
                    } else {
                        None
                    };
                    let formatted = match detail {
                        Some(d) if !d.is_empty() => format!("{err_name}: {d}"),
                        _ => err_name.to_string(),
                    };
                    return Err(KeyringError::BackendError(formatted));
                }
                _ => {
                    // Ignore unrelated signals or messages while awaiting our reply serial.
                }
            }
        }
    }

    fn read_message(&mut self) -> Result<DbusMessage, KeyringError> {
        let mut fixed = [0u8; 16];
        self.stream
            .read_exact(&mut fixed)
            .map_err(|e| KeyringError::BackendError(format!("D-Bus read failed: {e}")))?;

        let endian = Endian::from_byte(fixed[0])?;
        let msg_type = fixed[1];
        let version = fixed[3];
        if version != 1 {
            return Err(KeyringError::BackendError(format!(
                "Unsupported D-Bus protocol version: {version}"
            )));
        }

        let body_len = endian.read_u32(&fixed[4..8]) as usize;
        let fields_len = endian.read_u32(&fixed[12..16]) as usize;
        if fields_len > MAX_HEADER_FIELDS_LEN || body_len > MAX_BODY_LEN {
            return Err(KeyringError::BackendError(
                "D-Bus message exceeded safety size limit".to_string(),
            ));
        }

        let padded_fields_len = (fields_len + 7) & !7;
        let mut fields_buf = vec![0u8; padded_fields_len];
        self.stream
            .read_exact(&mut fields_buf)
            .map_err(|e| KeyringError::BackendError(format!("D-Bus header read failed: {e}")))?;

        let mut body = vec![0u8; body_len];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| KeyringError::BackendError(format!("D-Bus body read failed: {e}")))?;

        let mut reader = DbusReader::new(&fields_buf[..fields_len], endian);
        let mut reply_serial = None;
        let mut path = None;
        let mut interface = None;
        let mut member = None;
        let mut error_name = None;
        let mut signature = None;

        while reader.pos < fields_len {
            reader.align_to(8)?;
            if reader.pos >= fields_len {
                break;
            }
            let code = reader.read_u8()?;
            let field_sig = reader.read_sig()?.to_string();
            match (code, field_sig.as_str()) {
                (FIELD_PATH, "o") => path = Some(reader.read_str()?.to_string()),
                (FIELD_INTERFACE, "s") => interface = Some(reader.read_str()?.to_string()),
                (FIELD_MEMBER, "s") => member = Some(reader.read_str()?.to_string()),
                (FIELD_ERROR_NAME, "s") => error_name = Some(reader.read_str()?.to_string()),
                (FIELD_REPLY_SERIAL, "u") => reply_serial = Some(reader.read_u32()?),
                (FIELD_SIGNATURE, "g") => signature = Some(reader.read_sig()?.to_string()),
                _ => reader.skip_signature(&field_sig)?,
            }
        }

        Ok(DbusMessage {
            endian,
            msg_type,
            reply_serial,
            path,
            interface,
            member,
            error_name,
            signature,
            body,
        })
    }

    fn open_plain_session(&mut self) -> Result<String, KeyringError> {
        let reply = self.call(
            SECRET_SERVICE_DEST,
            SECRET_SERVICE_PATH,
            SERVICE_IFACE,
            "OpenSession",
            "sv",
            |w| {
                w.write_str("plain");
                w.write_sig("s");
                w.write_str("");
            },
        )?;
        let mut r = DbusReader::new(&reply.body, reply.endian);
        let _ = r.skip_one_type("v")?;
        Ok(r.read_str()?.to_string())
    }

    fn close_session(&mut self, session_path: &str) {
        let _ = self.call(
            SECRET_SERVICE_DEST,
            session_path,
            SESSION_IFACE,
            "Close",
            "",
            |_| {},
        );
    }

    fn resolve_default_collection(&mut self) -> Result<String, KeyringError> {
        if let Ok(reply) = self.call(
            SECRET_SERVICE_DEST,
            SECRET_SERVICE_PATH,
            SERVICE_IFACE,
            "ReadAlias",
            "s",
            |w| w.write_str("default"),
        ) {
            let mut r = DbusReader::new(&reply.body, reply.endian);
            if let Ok(path) = r.read_str()
                && !path.is_empty()
                && path != "/"
            {
                return Ok(path.to_string());
            }
        }
        Ok(DEFAULT_COLLECTION_ALIAS_PATH.to_string())
    }

    fn search_items(
        &mut self,
        attrs: &[(&str, &str)],
    ) -> Result<(Vec<String>, Vec<String>), KeyringError> {
        let reply = self.call(
            SECRET_SERVICE_DEST,
            SECRET_SERVICE_PATH,
            SERVICE_IFACE,
            "SearchItems",
            "a{ss}",
            |w| w.write_dict_ss(attrs),
        )?;
        let mut r = DbusReader::new(&reply.body, reply.endian);
        let unlocked = r.read_object_path_array()?;
        let locked = r.read_object_path_array()?;
        Ok((unlocked, locked))
    }

    fn unlock_objects(&mut self, paths: &[String]) -> Result<Vec<String>, KeyringError> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let reply = self.call(
            SECRET_SERVICE_DEST,
            SECRET_SERVICE_PATH,
            SERVICE_IFACE,
            "Unlock",
            "ao",
            |w| {
                w.write_array(4, |arr| {
                    for p in paths {
                        arr.write_str(p);
                    }
                });
            },
        )?;
        let mut r = DbusReader::new(&reply.body, reply.endian);
        let mut unlocked = r.read_object_path_array()?;
        let prompt = r.read_str()?.to_string();
        if prompt != "/" && !prompt.is_empty() {
            self.complete_prompt(&prompt)?;
            unlocked.extend_from_slice(paths);
        }
        Ok(unlocked)
    }

    fn complete_prompt(&mut self, prompt_path: &str) -> Result<(), KeyringError> {
        if !self.allow_gui_prompt {
            return Err(KeyringError::BackendError(
                "OS keyring collection is locked and no graphical session is available for unlock prompt"
                    .to_string(),
            ));
        }

        let _ = self.call(
            SECRET_SERVICE_DEST,
            prompt_path,
            PROMPT_IFACE,
            "Prompt",
            "s",
            |w| w.write_str(""),
        )?;

        let _ = self.stream.set_read_timeout(Some(DBUS_PROMPT_TIMEOUT));
        let outcome = loop {
            let msg = match self.read_message() {
                Ok(m) => m,
                Err(e) => break Err(e),
            };
            if msg.msg_type == MSG_SIGNAL
                && msg.path.as_deref() == Some(prompt_path)
                && msg.interface.as_deref() == Some(PROMPT_IFACE)
                && msg.member.as_deref() == Some("Completed")
            {
                let mut r = DbusReader::new(&msg.body, msg.endian);
                let dismissed = r.read_bool()?;
                if dismissed {
                    break Err(KeyringError::BackendError(
                        "OS keyring prompt was dismissed".to_string(),
                    ));
                }
                break Ok(());
            }
        };
        let _ = self.stream.set_read_timeout(Some(DBUS_IO_TIMEOUT));
        outcome
    }

    fn get_item_secret(
        &mut self,
        item_path: &str,
        session_path: &str,
    ) -> Result<Option<String>, KeyringError> {
        let reply = self.call(
            SECRET_SERVICE_DEST,
            item_path,
            ITEM_IFACE,
            "GetSecret",
            "o",
            |w| w.write_str(session_path),
        )?;
        let mut r = DbusReader::new(&reply.body, reply.endian);
        r.align_to(8)?;
        let _ret_session = r.read_str()?;
        let _params = r.read_byte_array()?;
        let value_bytes = r.read_byte_array()?;
        let pass = String::from_utf8_lossy(value_bytes)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Ok(if pass.is_empty() { None } else { Some(pass) })
    }

    fn delete_item(&mut self, item_path: &str) -> Result<(), KeyringError> {
        if item_path.is_empty() || item_path == "/" {
            return Ok(());
        }
        let reply = self.call(
            SECRET_SERVICE_DEST,
            item_path,
            ITEM_IFACE,
            "Delete",
            "",
            |_| {},
        )?;
        let mut r = DbusReader::new(&reply.body, reply.endian);
        let prompt = r.read_str()?.to_string();
        if prompt != "/" && !prompt.is_empty() {
            self.complete_prompt(&prompt)?;
        }
        Ok(())
    }
}

pub fn get_password(account: &str) -> Result<Option<String>, KeyringError> {
    let Ok(mut client) = DbusClient::connect() else {
        return Ok(None);
    };
    get_password_on_client(&mut client, KEYRING_SERVICE_NAME, account)
}

fn get_password_on_client(
    client: &mut DbusClient,
    service: &str,
    account: &str,
) -> Result<Option<String>, KeyringError> {
    let Ok(session) = client.open_plain_session() else {
        return Ok(None);
    };

    let result = (|| {
        let (unlocked, locked) =
            client.search_items(&[("service", service), ("username", account)])?;
        let target_item = if let Some(first) = unlocked.first() {
            first.clone()
        } else if !locked.is_empty() {
            let newly_unlocked = client.unlock_objects(&locked)?;
            match newly_unlocked.into_iter().next() {
                Some(p) => p,
                None => return Ok(None),
            }
        } else {
            return Ok(None);
        };
        client.get_item_secret(&target_item, &session)
    })();

    client.close_session(&session);
    Ok(result.ok().flatten())
}

pub fn set_password(account: &str, secret: &str) -> Result<(), KeyringError> {
    let mut client = DbusClient::connect()?;
    set_password_on_client(&mut client, KEYRING_SERVICE_NAME, account, secret)
}

fn set_password_on_client(
    client: &mut DbusClient,
    service: &str,
    account: &str,
    secret: &str,
) -> Result<(), KeyringError> {
    let session = client.open_plain_session()?;

    let result = (|| {
        let collection_path = client.resolve_default_collection()?;
        let _ = client.unlock_objects(std::slice::from_ref(&collection_path))?;

        let existing_items = client
            .search_items(&[("service", service), ("username", account)])
            .map(|(mut u, l)| {
                u.extend(l);
                u
            })
            .unwrap_or_default();

        let item_label = if account == KEYRING_DEFAULT_USER {
            service.to_string()
        } else {
            format!("{service}:{account}")
        };

        let reply = client.call(
            SECRET_SERVICE_DEST,
            &collection_path,
            COLLECTION_IFACE,
            "CreateItem",
            "a{sv}(oayays)b",
            |w| {
                w.write_array(8, |props| {
                    props.pad_to(8);
                    props.write_str("org.freedesktop.Secret.Item.Label");
                    props.write_sig("s");
                    props.write_str(&item_label);

                    props.pad_to(8);
                    props.write_str("org.freedesktop.Secret.Item.Attributes");
                    props.write_sig("a{ss}");
                    props.write_dict_ss(&[
                        ("xdg:schema", GENERIC_SCHEMA_VALUE),
                        ("service", service),
                        ("username", account),
                    ]);
                });

                w.pad_to(8);
                w.write_str(&session);
                w.write_byte_array(&[]);
                w.write_byte_array(secret.as_bytes());
                w.write_str("text/plain");

                w.write_bool(true);
            },
        )?;

        let mut r = DbusReader::new(&reply.body, reply.endian);
        let mut created_item = r.read_str()?.to_string();
        let prompt = r.read_str()?.to_string();
        if prompt != "/" && !prompt.is_empty() {
            client.complete_prompt(&prompt)?;
            if created_item == "/" {
                created_item.clear();
            }
        }

        if !created_item.is_empty() && created_item != "/" {
            for old_item in existing_items {
                if old_item != created_item {
                    let _ = client.delete_item(&old_item);
                }
            }
        }

        Ok(())
    })();

    client.close_session(&session);
    result
}

pub fn delete_password(account: &str) -> Result<(), KeyringError> {
    let mut client = DbusClient::connect()?;
    delete_password_on_client(&mut client, KEYRING_SERVICE_NAME, account)
}

fn delete_password_on_client(
    client: &mut DbusClient,
    service: &str,
    account: &str,
) -> Result<(), KeyringError> {
    let (unlocked, locked) = client.search_items(&[("service", service), ("username", account)])?;
    if !locked.is_empty() {
        let _ = client.unlock_objects(&locked)?;
    }
    for item in unlocked.iter().chain(locked.iter()) {
        client.delete_item(item)?;
    }
    Ok(())
}

pub fn delete_all_passwords(vault_ids: &[String]) -> Result<(), KeyringError> {
    let mut client = DbusClient::connect()?;
    delete_all_passwords_on_client(&mut client, KEYRING_SERVICE_NAME, vault_ids)
}

fn delete_all_passwords_on_client(
    client: &mut DbusClient,
    service: &str,
    vault_ids: &[String],
) -> Result<(), KeyringError> {
    let mut items_to_delete = Vec::new();

    for acct in std::iter::once(KEYRING_DEFAULT_USER).chain(
        vault_ids
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != KEYRING_DEFAULT_USER),
    ) {
        if let Ok((u, l)) = client.search_items(&[("service", service), ("username", acct)]) {
            items_to_delete.extend(u);
            items_to_delete.extend(l);
        }
    }

    if let Ok((u, l)) = client.search_items(&[("service", service)]) {
        for p in u.into_iter().chain(l) {
            if !items_to_delete.contains(&p) {
                items_to_delete.push(p);
            }
        }
    }

    for item in &items_to_delete {
        let _ = client.delete_item(item);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum BusSocketEndpoint {
    Path(PathBuf),
    #[cfg(target_os = "linux")]
    Abstract(Vec<u8>),
}

fn connect_session_bus() -> Result<UnixStream, KeyringError> {
    if let Some(raw_addr) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") {
        let addr_str = raw_addr.to_string_lossy();
        let trimmed = addr_str.trim();
        if trimmed.is_empty() {
            return Err(KeyringError::BackendError(
                "DBUS_SESSION_BUS_ADDRESS is empty".to_string(),
            ));
        }
        let endpoints = parse_dbus_addresses(trimmed)?;
        let mut last_err = None;
        for ep in endpoints {
            match connect_endpoint(&ep) {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
        return Err(last_err.unwrap_or_else(|| {
            KeyringError::BackendError(
                "No usable Unix socket in DBUS_SESSION_BUS_ADDRESS".to_string(),
            )
        }));
    }

    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR")
        && !xdg.is_empty()
    {
        let fallback_sock = PathBuf::from(xdg).join("bus");
        if fallback_sock.exists() {
            return UnixStream::connect(&fallback_sock).map_err(|e| {
                KeyringError::BackendError(format!(
                    "Failed to connect to fallback D-Bus socket {}: {e}",
                    fallback_sock.display()
                ))
            });
        }
    }

    Err(KeyringError::BackendError(
        "DBUS_SESSION_BUS_ADDRESS is not set".to_string(),
    ))
}

fn connect_endpoint(endpoint: &BusSocketEndpoint) -> Result<UnixStream, KeyringError> {
    match endpoint {
        BusSocketEndpoint::Path(path) => UnixStream::connect(path).map_err(|e| {
            KeyringError::BackendError(format!(
                "Failed to connect to D-Bus socket {}: {e}",
                path.display()
            ))
        }),
        #[cfg(target_os = "linux")]
        BusSocketEndpoint::Abstract(name) => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name).map_err(|e| {
                KeyringError::BackendError(format!("Invalid abstract D-Bus socket name: {e}"))
            })?;
            UnixStream::connect_addr(&addr).map_err(|e| {
                KeyringError::BackendError(format!(
                    "Failed to connect to abstract D-Bus socket: {e}"
                ))
            })
        }
    }
}

fn parse_dbus_addresses(raw: &str) -> Result<Vec<BusSocketEndpoint>, KeyringError> {
    let mut endpoints = Vec::new();
    for entry in raw.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let Some(rest) = entry.strip_prefix("unix:") else {
            continue;
        };
        for kv in rest.split(',') {
            let Some((key, val)) = kv.split_once('=') else {
                continue;
            };
            match key.trim() {
                "path" => {
                    let decoded = percent_decode(val)?;
                    if !decoded.is_empty() {
                        let s = String::from_utf8(decoded).map_err(|e| {
                            KeyringError::BackendError(format!("Invalid D-Bus socket path: {e}"))
                        })?;
                        endpoints.push(BusSocketEndpoint::Path(PathBuf::from(s)));
                    }
                }
                #[cfg(target_os = "linux")]
                "abstract" => {
                    let decoded = percent_decode(val)?;
                    if !decoded.is_empty() {
                        endpoints.push(BusSocketEndpoint::Abstract(decoded));
                    }
                }
                "runtime" if val.trim() == "yes" => {
                    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR")
                        && !xdg.is_empty()
                    {
                        endpoints.push(BusSocketEndpoint::Path(PathBuf::from(xdg).join("bus")));
                    }
                }
                _ => {}
            }
        }
    }
    if endpoints.is_empty() {
        return Err(KeyringError::BackendError(format!(
            "Unsupported or malformed DBUS_SESSION_BUS_ADDRESS: {raw}"
        )));
    }
    Ok(endpoints)
}

fn percent_decode(input: &str) -> Result<Vec<u8>, KeyringError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(KeyringError::BackendError(
                    "Incomplete percent-escape in D-Bus address".to_string(),
                ));
            }
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, KeyringError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(KeyringError::BackendError(
            "Invalid hex digit in D-Bus percent-escape".to_string(),
        )),
    }
}

fn effective_uid_hex() -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata(Path::new("/proc/self")).ok()?.uid();
    let uid_decimal = uid.to_string();
    let mut hex = String::with_capacity(uid_decimal.len() * 2);
    for &b in uid_decimal.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    Some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    struct FakeSecretItem {
        path: String,
        attrs: HashMap<String, String>,
        secret: Vec<u8>,
    }

    fn spawn_fake_secret_service(listener: UnixListener) -> std::thread::JoinHandle<()> {
        let store: Arc<Mutex<Vec<FakeSecretItem>>> = Arc::new(Mutex::new(Vec::new()));
        std::thread::spawn(move || {
            let mut next_id = 1usize;
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else {
                    break;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut nul = [0u8; 1];
                if stream.read_exact(&mut nul).is_err() || nul[0] != 0 {
                    break;
                }
                let Ok(auth_line) = read_line_crlf(&mut stream) else {
                    break;
                };
                if !auth_line.starts_with("AUTH EXTERNAL") {
                    break;
                }
                if auth_line == "AUTH EXTERNAL" {
                    let _ = stream.write_all(b"DATA\r\n");
                    let _ = read_line_crlf(&mut stream);
                }
                if stream
                    .write_all(b"OK 0123456789abcdef0123456789abcdef\r\n")
                    .is_err()
                {
                    break;
                }
                let Ok(begin_line) = read_line_crlf(&mut stream) else {
                    break;
                };
                if begin_line != "BEGIN" {
                    break;
                }

                let mut server_serial = 100u32;
                while let Ok(call) = read_server_call(&mut stream) {
                    let call_serial = call.serial;
                    let path = call.path;
                    let iface = call.iface;
                    let member = call.member;
                    let body = call.body;
                    let endian = call.endian;
                    match (iface.as_str(), member.as_str()) {
                        ("org.freedesktop.DBus", "Hello") => {
                            send_return(&mut stream, server_serial, call_serial, "s", |w| {
                                w.write_str(":1.42");
                            });
                        }
                        (SERVICE_IFACE, "OpenSession") => {
                            send_return(&mut stream, server_serial, call_serial, "vo", |w| {
                                w.write_sig("s");
                                w.write_str("");
                                w.write_str("/org/freedesktop/secrets/session/s1");
                            });
                        }
                        (SESSION_IFACE, "Close") => {
                            send_return(&mut stream, server_serial, call_serial, "", |_| {});
                            break;
                        }
                        (SERVICE_IFACE, "ReadAlias") => {
                            send_return(&mut stream, server_serial, call_serial, "o", |w| {
                                w.write_str("/org/freedesktop/secrets/collection/login");
                            });
                        }
                        (SERVICE_IFACE, "Unlock") => {
                            let mut r = DbusReader::new(&body, endian);
                            let paths = r.read_object_path_array().unwrap_or_default();
                            send_return(&mut stream, server_serial, call_serial, "aoo", |w| {
                                w.write_array(4, |arr| {
                                    for p in &paths {
                                        arr.write_str(p);
                                    }
                                });
                                w.write_str("/");
                            });
                        }
                        (COLLECTION_IFACE, "CreateItem") => {
                            let (attrs, secret_val) = parse_create_item(&body, endian);
                            let mut guard = store.lock().unwrap();
                            let item_path = if let Some(existing) =
                                guard.iter_mut().find(|it| it.attrs == attrs)
                            {
                                existing.secret = secret_val;
                                existing.path.clone()
                            } else {
                                let p =
                                    format!("/org/freedesktop/secrets/collection/login/{next_id}");
                                next_id += 1;
                                guard.push(FakeSecretItem {
                                    path: p.clone(),
                                    attrs,
                                    secret: secret_val,
                                });
                                p
                            };
                            send_return(&mut stream, server_serial, call_serial, "oo", |w| {
                                w.write_str(&item_path);
                                w.write_str("/");
                            });
                        }
                        (SERVICE_IFACE, "SearchItems") => {
                            let query = parse_dict_ss(&body, endian);
                            let guard = store.lock().unwrap();
                            let matched: Vec<String> = guard
                                .iter()
                                .filter(|it| {
                                    query.iter().all(|(k, v)| {
                                        it.attrs.get(k).map(String::as_str) == Some(v)
                                    })
                                })
                                .map(|it| it.path.clone())
                                .collect();
                            send_return(&mut stream, server_serial, call_serial, "aoao", |w| {
                                w.write_array(4, |arr| {
                                    for p in &matched {
                                        arr.write_str(p);
                                    }
                                });
                                w.write_array(4, |_| {});
                            });
                        }
                        (ITEM_IFACE, "GetSecret") => {
                            let mut r = DbusReader::new(&body, endian);
                            let sess = r.read_str().unwrap_or("/").to_string();
                            let guard = store.lock().unwrap();
                            let secret = guard
                                .iter()
                                .find(|it| it.path == path)
                                .map(|it| it.secret.clone())
                                .unwrap_or_default();
                            send_return(&mut stream, server_serial, call_serial, "(oayays)", |w| {
                                w.pad_to(8);
                                w.write_str(&sess);
                                w.write_byte_array(&[]);
                                w.write_byte_array(&secret);
                                w.write_str("text/plain");
                            });
                        }
                        (ITEM_IFACE, "Delete") => {
                            let mut guard = store.lock().unwrap();
                            guard.retain(|it| it.path != path);
                            send_return(&mut stream, server_serial, call_serial, "o", |w| {
                                w.write_str("/");
                            });
                        }
                        ("STOP", "STOP") => break,
                        _ => break,
                    }
                    server_serial += 1;
                }
            }
        })
    }

    fn read_line_crlf(stream: &mut UnixStream) -> std::io::Result<String> {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        loop {
            stream.read_exact(&mut b)?;
            out.push(b[0]);
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
        }
    }

    struct ServerCall {
        serial: u32,
        path: String,
        iface: String,
        member: String,
        body: Vec<u8>,
        endian: Endian,
    }

    fn read_server_call(stream: &mut UnixStream) -> Result<ServerCall, ()> {
        let mut fixed = [0u8; 16];
        stream.read_exact(&mut fixed).map_err(|_| ())?;
        let endian = Endian::from_byte(fixed[0]).map_err(|_| ())?;
        let body_len = endian.read_u32(&fixed[4..8]) as usize;
        let serial = endian.read_u32(&fixed[8..12]);
        let fields_len = endian.read_u32(&fixed[12..16]) as usize;
        let padded = (fields_len + 7) & !7;
        let mut fields = vec![0u8; padded];
        stream.read_exact(&mut fields).map_err(|_| ())?;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).map_err(|_| ())?;

        let mut r = DbusReader::new(&fields[..fields_len], endian);
        let mut path = String::new();
        let mut iface = String::new();
        let mut member = String::new();
        while r.pos < fields_len {
            r.align_to(8).map_err(|_| ())?;
            if r.pos >= fields_len {
                break;
            }
            let code = r.read_u8().map_err(|_| ())?;
            let sig = r.read_sig().map_err(|_| ())?.to_string();
            match (code, sig.as_str()) {
                (FIELD_PATH, "o") => path = r.read_str().map_err(|_| ())?.to_string(),
                (FIELD_INTERFACE, "s") => iface = r.read_str().map_err(|_| ())?.to_string(),
                (FIELD_MEMBER, "s") => member = r.read_str().map_err(|_| ())?.to_string(),
                _ => r.skip_signature(&sig).map_err(|_| ())?,
            }
        }
        Ok(ServerCall {
            serial,
            path,
            iface,
            member,
            body,
            endian,
        })
    }

    fn send_return(
        stream: &mut UnixStream,
        serial: u32,
        reply_serial: u32,
        sig: &str,
        write_body: impl FnOnce(&mut DbusWriter),
    ) {
        let mut body = DbusWriter::new();
        write_body(&mut body);

        let mut frame = DbusWriter::new();
        frame
            .buf
            .extend_from_slice(&[b'l', MSG_METHOD_RETURN, 0, 1]);
        frame.write_u32(body.buf.len() as u32);
        frame.write_u32(serial);
        frame.write_array(8, |hdr| {
            hdr.pad_to(8);
            hdr.write_u8(FIELD_REPLY_SERIAL);
            hdr.write_sig("u");
            hdr.write_u32(reply_serial);
            if !sig.is_empty() {
                hdr.pad_to(8);
                hdr.write_u8(FIELD_SIGNATURE);
                hdr.write_sig("g");
                hdr.write_sig(sig);
            }
        });
        frame.pad_to(8);
        frame.buf.extend_from_slice(&body.buf);
        let _ = stream.write_all(&frame.buf);
    }

    fn parse_dict_ss(buf: &[u8], endian: Endian) -> HashMap<String, String> {
        let mut r = DbusReader::new(buf, endian);
        let byte_len = r.read_u32().unwrap_or(0) as usize;
        let _ = r.align_to(8);
        let end = r.pos + byte_len;
        let mut out = HashMap::new();
        while r.pos < end {
            let _ = r.align_to(8);
            if r.pos >= end {
                break;
            }
            let k = r.read_str().unwrap_or("").to_string();
            let v = r.read_str().unwrap_or("").to_string();
            out.insert(k, v);
        }
        out
    }

    fn parse_create_item(buf: &[u8], endian: Endian) -> (HashMap<String, String>, Vec<u8>) {
        let mut r = DbusReader::new(buf, endian);
        let props_len = r.read_u32().unwrap() as usize;
        r.align_to(8).unwrap();
        let props_end = r.pos + props_len;
        let mut attrs = HashMap::new();
        while r.pos < props_end {
            r.align_to(8).unwrap();
            if r.pos >= props_end {
                break;
            }
            let prop_key = r.read_str().unwrap();
            let var_sig = r.read_sig().unwrap().to_string();
            if prop_key == "org.freedesktop.Secret.Item.Attributes" && var_sig == "a{ss}" {
                let dict_len = r.read_u32().unwrap() as usize;
                r.align_to(8).unwrap();
                let dict_end = r.pos + dict_len;
                while r.pos < dict_end {
                    r.align_to(8).unwrap();
                    if r.pos >= dict_end {
                        break;
                    }
                    let k = r.read_str().unwrap().to_string();
                    let v = r.read_str().unwrap().to_string();
                    attrs.insert(k, v);
                }
            } else {
                r.skip_signature(&var_sig).unwrap();
            }
        }
        r.align_to(8).unwrap();
        let _sess = r.read_str().unwrap();
        let _params = r.read_byte_array().unwrap();
        let secret = r.read_byte_array().unwrap().to_vec();
        let _ctype = r.read_str().unwrap();
        let _replace = r.read_bool().unwrap();
        (attrs, secret)
    }

    #[test]
    fn test_parse_dbus_addresses_and_percent_decoding() {
        let parsed =
            parse_dbus_addresses("tcp:host=127.0.0.1;unix:path=/tmp/my%20bus%2dsock,guid=001122")
                .unwrap();
        assert_eq!(
            parsed,
            vec![BusSocketEndpoint::Path(PathBuf::from("/tmp/my bus-sock"))]
        );
        assert!(parse_dbus_addresses("tcp:host=127.0.0.1").is_err());
        assert!(percent_decode("/tmp/%ZZ").is_err());
    }

    #[test]
    fn test_dbus_secret_service_roundtrip_multi_vault_over_unix_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("bus.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server_thread = spawn_fake_secret_service(listener);

        let connect_fake = || {
            let stream = UnixStream::connect(&sock_path).unwrap();
            DbusClient::from_stream(stream, false).unwrap()
        };

        let svc = "dotler-mock-svc";
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "default").unwrap(),
            None
        );

        set_password_on_client(&mut connect_fake(), svc, "default", "default-passphrase").unwrap();
        set_password_on_client(
            &mut connect_fake(),
            svc,
            "a1b2c3d4e5f60718",
            "vault-alpha-secret",
        )
        .unwrap();
        set_password_on_client(
            &mut connect_fake(),
            svc,
            "deadbeefcafebabe",
            "vault-beta-secret",
        )
        .unwrap();

        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "default")
                .unwrap()
                .as_deref(),
            Some("default-passphrase")
        );
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "a1b2c3d4e5f60718")
                .unwrap()
                .as_deref(),
            Some("vault-alpha-secret")
        );
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "deadbeefcafebabe")
                .unwrap()
                .as_deref(),
            Some("vault-beta-secret")
        );

        // Overwrite in-place via replace=true
        set_password_on_client(
            &mut connect_fake(),
            svc,
            "a1b2c3d4e5f60718",
            "rotated-alpha-secret",
        )
        .unwrap();
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "a1b2c3d4e5f60718")
                .unwrap()
                .as_deref(),
            Some("rotated-alpha-secret")
        );

        // Single vault deletion preserves default and other vault
        delete_password_on_client(&mut connect_fake(), svc, "a1b2c3d4e5f60718").unwrap();
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "a1b2c3d4e5f60718").unwrap(),
            None
        );
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "default")
                .unwrap()
                .as_deref(),
            Some("default-passphrase")
        );
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "deadbeefcafebabe")
                .unwrap()
                .as_deref(),
            Some("vault-beta-secret")
        );

        // Bulk deletion clears remaining entries
        delete_all_passwords_on_client(&mut connect_fake(), svc, &["deadbeefcafebabe".to_string()])
            .unwrap();
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "default").unwrap(),
            None
        );
        assert_eq!(
            get_password_on_client(&mut connect_fake(), svc, "deadbeefcafebabe").unwrap(),
            None
        );

        if let Ok(mut stop_conn) = UnixStream::connect(&sock_path) {
            let _ = stop_conn.write_all(&[1u8]);
        }
        drop(std::fs::remove_file(&sock_path));
        drop(tmp);
        let _ = server_thread.join();
    }

    #[test]
    fn test_live_session_bus_without_external_binaries_when_unlocked() {
        let Ok(stream) = connect_session_bus() else {
            return;
        };
        let Ok(mut client) = DbusClient::from_stream(stream, false) else {
            return;
        };

        let svc = format!("dotler-ephemeral-test-{:016x}", crate::crypto::random_u64());
        let acct = "ephemeral-vault";

        if set_password_on_client(&mut client, &svc, acct, "native-dbus-secret-123").is_ok() {
            let mut reader_client =
                DbusClient::from_stream(connect_session_bus().unwrap(), false).unwrap();
            assert_eq!(
                get_password_on_client(&mut reader_client, &svc, acct)
                    .unwrap()
                    .as_deref(),
                Some("native-dbus-secret-123")
            );

            let mut updater_client =
                DbusClient::from_stream(connect_session_bus().unwrap(), false).unwrap();
            set_password_on_client(&mut updater_client, &svc, acct, "native-dbus-secret-456")
                .unwrap();

            let mut verify_client =
                DbusClient::from_stream(connect_session_bus().unwrap(), false).unwrap();
            assert_eq!(
                get_password_on_client(&mut verify_client, &svc, acct)
                    .unwrap()
                    .as_deref(),
                Some("native-dbus-secret-456")
            );

            let mut del_client =
                DbusClient::from_stream(connect_session_bus().unwrap(), false).unwrap();
            delete_password_on_client(&mut del_client, &svc, acct).unwrap();

            let mut final_client =
                DbusClient::from_stream(connect_session_bus().unwrap(), false).unwrap();
            assert_eq!(
                get_password_on_client(&mut final_client, &svc, acct).unwrap(),
                None
            );
        }
    }
}
