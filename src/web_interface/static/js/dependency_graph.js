var allConnectedNodes;
var allNodes;
var dataset;
var graphOptions;
var groupOptions;
var highlightActive = false;
var network;

function dependencyGraph(nodes, edges, groups, colors) {
    let graphCanvas = $("#dependencyGraph")[0];

    dataset = {
        nodes: new vis.DataSet(nodes),
        edges: new vis.DataSet(edges)
    };

    // map group names to colors --> {'mime/type': {color: '#...'}}
    // jshint ignore:start
    groupOptions = groups.reduce((obj, curr, i) => {return {...obj, [curr]: {color: colors[i]}}}, {});
    // jshint ignore:end

    // set the graph options. Most of this is physics model initialization
    graphOptions = {
        nodes: {
            shape: 'dot',
            font: {
                size: 18,
                face: 'Tahoma'
            }
        },
        groups: groupOptions,
        edges: {
            color: { inherit: true },
            width: 0.5,
            arrows: { to: true },
        },
        interaction: {
            dragNodes: false,
        },
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                theta: 0.8,
                springLength: 40,
                springConstant: 0.05,
                damping: 0.4,
                avoidOverlap: 0.1,
            },
            maxVelocity: 2000,
            minVelocity: 0.0,
            timestep: 0.05,
            adaptiveTimestep: true,
            stabilization: {
              enabled: false
            }
        },
        layout: {
            randomSeed: 0,
            improvedLayout: false,
        }
    };

    // draw all components
    network = drawNetwork(dataset, graphOptions, graphCanvas);
    drawLegend(groups, colors);
    drawNodesList();
    drawDetails();

    // register event handlers
    network.on("click", neighbourhoodHighlight);
    $('#nodesList').click(nodeListSelectionHandler);
    $('#nodeFilter').keyup(filterNodesList);
}

function drawLegend(groups, colors) {
    // draw the legend
    let legend = $('#legend');
    for (let i = 0; i < groups.length; i++) {
        legend.append('<div><span style="color: ' + colors[i] + ';">&#9679;</span> ' + groups[i] + '</div>');
    }
}

function filterNodesList() {
    // filter nodes list event handler
    try {
        // the filter input supports regex
        var expr = new RegExp($(this).val(), 'i');
    } catch(SyntaxError) {
        // invalid search
        return;
    }

    $("#nodesList > div").each(function(){
        // hide all nodes in the list that are filtered out, show the rest
        let mime = $(this).find('a')[0].dataset.nodemime;
        let name = $(this).find('a')[0].dataset.nodelabel;

        // we search both name and mime
        if (mime.search(expr) < 0 && name.search(expr) < 0) {
            $(this).fadeOut();
        } else {
            $(this).show();
        }
    });
}

function drawNodesList() {
    let nodesList = $('#nodesList');
    $('#nodeFilter')[0].value = '';
    nodesList.empty();

    for (let nodeId in allNodes) {
        let node = dataset.nodes.get(nodeId);
        let color = groupOptions[node.group].color;
        if (node.label !== undefined) {
            nodesList.append('<div><span style="color: ' + color + ';">&#9679;</span>&nbsp;<a href="#" class="text-dark" data-nodeid="' + node.id + '" data-nodelabel="' + node.label + '" data-nodemime="' + node.group + '" style="text-decoration: none;">' + node.label + '</a></div>');
        }
    }
}

function drawDetails() {
    // get details and flush contents
    let details = $('#detailsBody');
    details.empty();

    // check if something is selected
    let selected = network.getSelectedNodes();
    if (selected.length == 0) {
        details.append('<div>No node selected</div>');
        return;
    }

    // show node details
    let node = dataset.nodes.get(selected[0]);
    let color = groupOptions[node.group].color;
    details.append(`
        <div>
            <span class="font-weight-bold">Analysis:&nbsp;</span><a target="_blank" href="/analysis/${node.entity}">&#x1F517;</a>
        </div>
        <div>
            <span class="font-weight-bold">Node:&nbsp;</span><span style="color: ${color};">&#9679;</span>&nbsp;${node.label}
        </div>
        <div>
            <span class="font-weight-bold">Mime:&nbsp;</span>${node.group}
        </div>
        <div>
            <span class="font-weight-bold">Full:&nbsp;</span>${node.full_file_type}
        </div>`
    );
}

function drawNetwork(dataset, graphOptions, canvas) {
    // create the network on an empty canvas
    let network = new vis.Network(canvas, dataset, graphOptions,  main = "Dependency Graph");
    allNodes = dataset.nodes.get({ returnType: "Object" });

    // get a decent stabilization before starting a 60 second timeout that
    // aborts the physics simulation to preserve resources
    network.on("stabilizationIterationsDone", function (params) {
        setTimeout(() => {
            network.stopSimulation();
            network.setOptions( { physics: false } );
        }, 60000);
    });
    network.stabilize(200);

    return network;
}

function nodeListSelectionHandler(ev) {
    let ref = ev.target;

    // if the user clicked a link on the nodes list, this will be defined
    if (ref.dataset.nodeid !== undefined) {
        // we then programmatically select the node in the network...
        network.selectNodes([ref.dataset.nodeid]);

        // ... and invoke the selection handler by hand, because vis.js does
        // not fire a click event in this case.
        let params = {nodes: network.getSelectedNodes()};
        neighbourhoodHighlight(params);
    }
}

// adapted source from visjs example:
// https://visjs.github.io/vis-network/examples/network/exampleApplications/neighbourhoodHighlight.html
function neighbourhoodHighlight(params) {
    // if something is selected:
    if (params.nodes.length > 0) {
        highlightActive = true;
        var i, j;
        var selectedNode = params.nodes[0];
        var degrees = 1;
        network.focus(selectedNode, {scale: 0.4, animation: {easingFunction: 'easeInOutQuad'}});
 
        // mark all nodes as hard to read.
        for (let nodeId in allNodes) {
            allNodes[nodeId].color = "rgba(200,200,200,0.5)";
            if (allNodes[nodeId].hiddenLabel === undefined) {
                allNodes[nodeId].hiddenLabel = allNodes[nodeId].label;
                allNodes[nodeId].label = undefined;
            }
        }
 
        var connectedNodes = network.getConnectedNodes(selectedNode);
        allConnectedNodes = [];
 
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
        for (let nodeId in allNodes) {
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
    for (let nodeId in allNodes) {
        if (allNodes.hasOwnProperty(nodeId)) {
            updateArray.push(allNodes[nodeId]);
        }
    }
    dataset.nodes.update(updateArray);

    // re-draw nodes list and node detail view
    drawNodesList();
    drawDetails();
}
