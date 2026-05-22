( function() {
    document.querySelectorAll('.review-tab').forEach(tab => {
  tab.addEventListener('click', (e)=> {
    // Remove active class from all tabs
    document.querySelectorAll('.review-tab').forEach(t => t.classList.remove('active'));

    // Add active class to clicked tab
    tab.classList.add('active'); 

    const target = e.currentTarget.dataset.tab;
    document.querySelectorAll('.review-panel').forEach(panel => {
        panel.classList.add('d-none');
    });

    const targetPanel = document.getElementById('panel-' + target);
    if (targetPanel) targetPanel.classList.remove('d-none'); 
  });
});

document.querySelectorAll(".queue-search").forEach((input) => {
  input.addEventListener("input", () => {
    const term = input.value.toLowerCase().trim();
    document.querySelectorAll(`#${input.dataset.table} tbody tr`).forEach((row) => {
      row.style.display = row.textContent.toLowerCase().includes(term) ? "" : "none";
    });
  });
});

})();