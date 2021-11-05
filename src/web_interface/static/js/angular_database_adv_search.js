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