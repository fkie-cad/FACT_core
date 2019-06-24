;(function ( $, window, document, undefined ) {
    'use strict';

    var pluginName = 'lineLine',
        defaults = {
            startsFrom: 0,
            className: 'lineline'
        };

    function Plugin( element, options ) {
        this.element = element;
        this.options = $.extend( {}, defaults, options);

        this._defaults = defaults;
        this._name = pluginName;

        this.init();
    }

    Plugin.prototype.init = function () {
        var self = this;
        
        var lines = $(self.element).html().split('\n');
        var lineCount = lines.length;
        
        var html = '<div class="' + self.options.className + '"><table class="' + self.options.className + '-code" border="0" cellspacing="0" cellpadding="0">';
        for (var i = self.options.startsFrom; i < lineCount; i++){
            html += '<tr><td class="' + self.options.className + '-numbers">' + (i + 1) + '</td><td class="' + self.options.className + '-lines">' + lines[i] + '</td></tr>';
        }
        html += '</table></div>';
        
        $(self.element).before(html);
        $(self.element).remove();
    };

    $.fn[pluginName] = function ( options ) {
        return this.each(function () {
            if (!$.data(this, 'plugin_' + pluginName)) {
                $.data(this, 'plugin_' + pluginName,
                new Plugin( this, options ));
            }
        });
    };

})( jQuery, window, document );
