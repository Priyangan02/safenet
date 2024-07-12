
document.addEventListener('DOMContentLoaded', ()=> {
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
     
    const table = document.getElementById('myTable');

    $('#myTable').DataTable({
        // responsive: true
    });
    
 
    
   
})