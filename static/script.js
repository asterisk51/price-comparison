document.addEventListener('DOMContentLoaded', function() {
    const btn = document.querySelector('.btn');
    btn.addEventListener('mouseover', function() {
        btn.style.transform = 'scale(1.05)';
    });
    btn.addEventListener('mouseout', function() {
        btn.style.transform = 'scale(1)';
    });
});
