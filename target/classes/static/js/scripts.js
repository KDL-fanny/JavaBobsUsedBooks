// Common JavaScript functions for Bob's Used Books

// Function to confirm deletion of items
function confirmDelete(itemType, callback) {
    if (confirm('Are you sure you want to delete this ' + itemType + '?')) {
        callback();
    }
}

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
