window.onload = function () {
    tocbot.init({
	// Where to render the table of contents.
	tocSelector: '.js-toc',
	// Where to grab the headings to build the table of contents.
	contentSelector: '.main-content',
	// listClass: '.nav-list',
	// listItemClass: '.nav-list-item',
	// linkClass: '.nav-list-link',
	// Which headings to grab inside of the contentSelector element.
	// activeListItemClass: 'active',
	headingSelector: 'h2, h3, h4, h5, h6',
	// For headings inside relative or absolute positioned containers within content.
	hasInnerContainers: true,
	collapseDepth: 3
    });
}

function showToc() {
  document.getElementById("onpage-toc").classList.toggle("toc-show");
}

// Close the dropdown menu if the user clicks outside of it
window.onclick = function(event) {
  if (!event.target.matches('.toc-dropup')) {
    var dropdowns = document.getElementsByClassName("onpage-toc");
    var i;
    for (i = 0; i < dropdowns.length; i++) {
      var openDropdown = dropdowns[i];
      if (openDropdown.classList.contains('toc-show')) {
        openDropdown.classList.remove('toc-show');
      }
    }
  }
}
