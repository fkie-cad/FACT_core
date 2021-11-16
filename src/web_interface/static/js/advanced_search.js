function hide_checkbox() {
    if ($("#only_firmware").is(':checked')) {
        $("#inverted_div").show();
    } else {
        $("#inverted_div").hide();
    }
}
var app = angular.module('myApp', []);

app.config(['$interpolateProvider', function($interpolateProvider) {
    $interpolateProvider.startSymbol('{a');
    $interpolateProvider.endSymbol('a}');
}]);

app.controller('formCtrl', function($scope) {
    $scope.firstname = "complete";
    $scope.data = database_structure;
    $scope.plugins = Object.keys($scope.data);
});