var nodes, groups, edges, network, legend_network, allNodes;
    var highlightActive = false;

    // convenience method to stringify a JSON object
    function toJSON(obj) {
        return JSON.stringify(obj, null, 4);
    }

    var my_nodes = []
    var my_edges = []
    groups = []

    var graph_container = document.getElementById("dependencyGraph");
    var legend_container = document.getElementById("dependencyGraphLegend");

    for (i in get_nodes) {
        my_nodes[i] = {id: get_nodes[i].id, label: get_nodes[i].label, group: get_nodes[i].group, full_file_type: get_nodes[i].full_file_type}
    }
    for (i in get_edges) {
        my_edges[i] = {id: get_edges[i].id, from: get_edges[i].source, to: get_edges[i].target}
    }
    for (i in get_groups) {
        groups.push(get_groups[i])
    }

    // create an array with nodes
    nodes = new vis.DataSet();
    nodes.add(my_nodes);

    // create a legend
    // and change group colors
    var legend_nodes = new vis.DataSet();
    var legend_nodes_array = [];
    var x = 0;
    var y = 0;
    var step = 60;

    var group_options = {};
   
    if (typeof color_list === 'undefined' || color_list.length <= 0) {
        // bootstrap colors cyan, yellow, pink, blue, purple, orange
        color_list = ['#17a2b8', '#ffc107', '#e83e8c', '#007bff', '#6f42c1', '#fd7e14'];
    }
    color_i = 0;

    var id = 1;
    var step_i = 0;
    for (j in groups) {
        legend_nodes_array.push({
            id: id,
            x: x,
            y: y + step * step_i,
            label: groups[j],
            group: groups[j],
            value: 1,
            fixed: true,
            physics: false
        });
        id = id + 1;
        step_i = step_i + 1;
        group_options [groups[j]] = {color: color_list[color_i]};
        color_i = (color_i + 1)%color_list.length;
    }
    legend_nodes.add(legend_nodes_array);

    // create an array with edges
    edges = new vis.DataSet();
    edges.add(my_edges);

    // create a network
    var data = {
        nodes: nodes,
        edges: edges,
    };

    var legend_data = {
        nodes: legend_nodes,
    };

    function draw_network() {

        var options = {
            nodes: {
                shape: 'dot',
                scaling: {
                    min: 10,
                    max: 30
                },
                font: {
                    size: 12,
                    face: 'Tahoma'
                }
            },
            groups: group_options,
            edges: {
                color:{inherit:true},
                width: 0.15,
                arrows: {
                    to: true
                }
            },
            interaction: {
                hideEdgesOnDrag: true,
                tooltipDelay: 200
            },
            physics: {
                forceAtlas2Based: {
                    gravitationalConstant: -129,
                    centralGravity: 0.16,
                    springLength: 0,
                    springConstant: 0.4,
                    damping: 0.85,
                    avoidOverlap: 0.46
                },
                minVelocity: 0.75,
                solver: 'forceAtlas2Based'
            }
        };

        network = new vis.Network(graph_container, data, options,  main = "Dependency Graph");

        allNodes = nodes.get({ returnType: "Object" });
        network.on("click", neighbourhoodHighlight);

        network.on("oncontext", contextMenu);

        network.on("stabilizationIterationsDone", function (params) {
            network.stopSimulation();
            network.setOptions( { physics: false } );
        });
        network.stabilize(100);
    };

    function draw_legend() {

        // create a legend graph
        var legend_options = {
            nodes: {
                shape: 'dot',
                scaling: {
                    min: 10,
                    max: 30
                },
                font: {
                    size: 12,
                    face: 'Tahoma'
                }
            },
            groups: group_options,
            interaction: {
                hideEdgesOnDrag: true,
                tooltipDelay: 200,
                dragNodes: false,
                dragView: false,
                zoomView: false
            },
            physics: {
                forceAtlas2Based: {
                    gravitationalConstant: -129,
                    centralGravity: 0.16,
                    springLength: 0,
                    springConstant: 0.4,
                    damping: 0.85,
                    avoidOverlap: 0.46
                },
                minVelocity: 0.75,
                solver: 'forceAtlas2Based'
            }
        };

        legend_network = new vis.Network(legend_container, legend_data, legend_options,  main = "Dependency Graph Legend");

        legend_network.on("stabilizationIterationsDone", function (params) {
            legend_network.stopSimulation();
            legend_network.setOptions( { physics: false } );
        });
        legend_network.stabilize(100);
    };

    function contextMenu(params) {
        params.event.preventDefault();
        $('#context-menu').modal()
        var nodeId = network.getNodeAt(params.pointer.DOM);
        var href = '/analysis/' + nodeId;
        var nodeLabel = allNodes[nodeId].label;
        var link = '<a href="' + href + '">' + nodeLabel + '</a>';
        var fileType = allNodes[nodeId].full_file_type;
        document.getElementById('node-link').innerHTML = link;
        document.getElementById('file-type').innerHTML = fileType;
    };



    function neighbourhoodHighlight(params) {
        // if something is selected:
        if (params.nodes.length > 0) {
            highlightActive = true;
            var i, j;
            var selectedNode = params.nodes[0];
            var degrees = 1;

            // mark all nodes as hard to read.
            for (var nodeId in allNodes) {
                allNodes[nodeId].color = "rgba(200,200,200,0.5)";
                if (allNodes[nodeId].hiddenLabel === undefined) {
                    allNodes[nodeId].hiddenLabel = allNodes[nodeId].label;
                    allNodes[nodeId].label = undefined;
                }
            }

            var connectedNodes = network.getConnectedNodes(selectedNode);
            var allConnectedNodes = [];

            // get the second degree nodes
            for (i = 1; i < degrees; i++) {
                for (j = 0; j < connectedNodes.length; j++) {
                    allConnectedNodes = allConnectedNodes.concat(
                        network.getConnectedNodes(connectedNodes[j])
                    );
                }
            }

            // all second degree nodes get a different color and their label back
            for (i = 0; i < allConnectedNodes.length; i++) {
                allNodes[allConnectedNodes[i]].color = "rgba(150,150,150,0.75)";
                if (allNodes[allConnectedNodes[i]].hiddenLabel !== undefined) {
                    allNodes[allConnectedNodes[i]].label =
                    allNodes[allConnectedNodes[i]].hiddenLabel;
                    allNodes[allConnectedNodes[i]].hiddenLabel = undefined;
                }
            }

            // all first degree nodes get their own color and their label back
            for (i = 0; i < connectedNodes.length; i++) {
                allNodes[connectedNodes[i]].color = undefined;
                if (allNodes[connectedNodes[i]].hiddenLabel !== undefined) {
                    allNodes[connectedNodes[i]].label =
                    allNodes[connectedNodes[i]].hiddenLabel;
                    allNodes[connectedNodes[i]].hiddenLabel = undefined;
                }
            }

            // the main node gets its own color and its label back.
            allNodes[selectedNode].color = undefined;
            if (allNodes[selectedNode].hiddenLabel !== undefined) {
                allNodes[selectedNode].label = allNodes[selectedNode].hiddenLabel;
                allNodes[selectedNode].hiddenLabel = undefined;
            }
        } else if (highlightActive === true) {
            // reset all nodes
            for (var nodeId in allNodes) {
                allNodes[nodeId].color = undefined;
                if (allNodes[nodeId].hiddenLabel !== undefined) {
                    allNodes[nodeId].label = allNodes[nodeId].hiddenLabel;
                    allNodes[nodeId].hiddenLabel = undefined;
                }
            }
            highlightActive = false;
        }

        // transform the object into an array
        var updateArray = [];
        for (nodeId in allNodes) {
            if (allNodes.hasOwnProperty(nodeId)) {
                updateArray.push(allNodes[nodeId]);
            }
        }
        nodes.update(updateArray);
    }

    window.addEventListener("load", () => {
        draw_network();
        draw_legend();
    });