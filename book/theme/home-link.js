(function () {
    const menuTitle = document.querySelector(".menu-title");
    if (!menuTitle) return;

    const root = typeof path_to_root === "string" ? path_to_root : "";
    const homeUrl = new URL(root, document.baseURI).href;

    const link = document.createElement("a");
    link.href = homeUrl;
    link.style.color = "inherit";
    link.style.textDecoration = "none";
    while (menuTitle.firstChild) {
        link.appendChild(menuTitle.firstChild);
    }
    menuTitle.appendChild(link);

    menuTitle.addEventListener("click", function (event) {
        if (event.target === menuTitle) {
            window.location.href = homeUrl;
        }
    });
})();
