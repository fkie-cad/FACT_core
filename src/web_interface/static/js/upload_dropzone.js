var upload_complete = false;
var file_name = null;

function get_progress_bar(file) {
    return file.previewElement.querySelector("[data-dz-uploadprogress]");
}

Dropzone.options.dropper = {
    init: function() {
        this.on('addedfile', function(file) {
            if (this.files.length > 1) {
                this.removeFile(this.files[0]);
            }
            file_name = file.name;
            upload_complete = false;
        });
    },
    chunksUploaded: function (file, done) {
        upload_complete = true;
        document.getElementById("file_name").value = file_name;
        get_progress_bar(file).style.width = "100%";
    },
    uploadprogress: function(file, progress, bytesSent) {
    if (file.previewElement && progress != 100) {
            get_progress_bar(file).style.width = progress + "%";
        }
    },
    paramName: 'file',
    chunking: true,
    forceChunking: true,
    uploadMultiple: false,
    url: '/upload-file',
    chunkSize: 4194304, // 4 MiB
    maxFilesize: 10000 // 10 GB
};

function validate_submit() {
    if (upload_complete) {
        return true;
    } else {
        alert("Error: No file selected or upload incomplete");
        return false;
    }
}
