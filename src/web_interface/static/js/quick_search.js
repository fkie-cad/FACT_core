var nav = {
    quickSearch: null,
    captions: null,
    dropDownMenu: null
};

class ElementVisibilityObserver extends IntersectionObserver {
    /**
     * An asynchronous observer that executes a callback when the visibility
     * of DOM elements change (e.g., display changes from 'block' to 'none'):
     * callback(element, isVisible).
     * 
     * This class is based on IntersectionObserver, which fires a callback when
     * the intersection between a target element and its ancestor/top-level
     * viewport changes. We can leverage upon the calculated intersectionRatio
     * to decide whether or not a given element is visible:
     * 
     * Given the document root as top-level ancestor of the observed element.
     * When the element is invisible, it can not intersect with the ancestor
     * within the viewport (i.e., the intersection ratio is 0). However, if it
     * is visible, there must be *some* kind of intersection with the root, as
     * it encapsulates all other elements. Thus, the intersection ratio *must*
     * be > 0.
     */
    constructor(callback) {
        // 1. set ancestor as document root
        let options = {
            root: document.documentElement,
        };

        // 2. init superclass and encapsulate passed callback
        super((entries, _) => {
            entries.forEach(entry => {
                callback(entry.target, entry.intersectionRatio > 0);
            });
        }, options);
    }
}

function quickSearch() {
    // search fact db
    let searchInput = nav.quickSearch[0].value
    window.location = '/database/quick_search?search_term=' + searchInput;
}

function expandQuickSearchCb() {
    // fade out navbar texts, let search bar grow
    nav.captions.fadeOut(250);
    nav.quickSearch.css('width', '500px');
}

function initQuickSearch() {
    nav.quickSearch = $('#quick_search_input');
    nav.dropDownMenu = $('.navbar-toggler');
    nav.captions = $('.hideable_caption');

    // neither bootstrap nor jquery appear to emit an event that allows us to
    // elegantly monitor the navbar expansion or collapse when the viewport size
    // changes. However, the quick search bar animations break once said events
    // occur. Thus, we must toggle them when necessary.
    // We can build our own event for this matter by monitoring an element,
    // i.e., the navbar drop down button, which is only visible when the navbar
    // collapses.
    let visibilityObserver = new ElementVisibilityObserver(
        toggleQuickSearchAnimationsCb
    );
    visibilityObserver.observe(nav.dropDownMenu[0]);
}

function shrinkQuickSearchCb() {
    // fade in navbar texts, let quicksearch bar grow
    nav.captions.fadeIn(250);
    nav.quickSearch.css('width', '120px');
}

function toggleQuickSearchAnimationsCb(_, isVisible) {
    // assert that quicksearch is deselected and faded out text is visible
    nav.quickSearch.trigger('blur');
    nav.captions.show();
    // set animation events depending on the visibility of the navbar's dropDown
    if(isVisible) {
        nav.quickSearch.css('position', ''); // adhere to bootstrap styling
        nav.quickSearch.css('right', '');
        nav.quickSearch.off('focus.search_expand');
        nav.quickSearch.off('blur.search_shrink');
    } else {
        nav.quickSearch.css('position', 'absolute'); // float above all nav items
        nav.quickSearch.css('right', '50px');
        nav.quickSearch.on('focus.search_expand', expandQuickSearchCb);
        nav.quickSearch.on('blur.search_shrink', shrinkQuickSearchCb);
    }
}
