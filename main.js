let menu = document.querySelector("#menu-bars");
let navbar = document.querySelector(".navbar");

menu.onclick = () => {
    menu.classList.toggle('fa-time');
    navbar.classList.toggle('active');
}

// var swiper = new Swiper(".home- s1ider", {
//         spaceBetween: 30,
//         centeredSlides: true,
//         autoplay: {
//             delay: 7500,
//             disableonInteraction: false,
//         },
//         pagination: {
//             el: ".swiper-pagination",
//             clickable: true,
//         },
//         loop: true,
//     })

// // const activePage = window.location.pathname;
// console.log(activePage);
