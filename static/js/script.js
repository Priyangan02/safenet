
$(document).ready(function () {
    const themeCheckBox = document.querySelector('.theme-controller');

    //ambil data dari local storage
    const savedTheme = localStorage.getItem('theme');
    document.body.setAttribute('data-theme', savedTheme);
    themeCheckBox.checked = savedTheme === 'black';
    themeCheckBox.addEventListener('change', () => {
        const newTheme = themeCheckBox.checked ? 'black' : 'light';
        localStorage.setItem('theme', newTheme);
        document.body.setAttribute('data-theme', newTheme);
    });
    $('#myTable').DataTable({
        "order": false,
        "columnDefs": [
            { "className": "dt-center", "targets": "_all" }
        ],
    });
    $('.dt_search  input').addClass('border border-gray-300 rounded-md px-4 py-2');

    // Adding Tailwind classes to other DataTables elements if necessary
    $('.dataTables_length select').addClass('border border-gray-300 rounded-md px-4 py-2');
    $('.dataTables_wrapper').addClass('mt-4');

})