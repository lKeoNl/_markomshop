// ОКНО КАТАЛОГА
const catalogBtn = document.getElementById('catalog-toggle');
  const catalogIcon = document.getElementById('catalog-icon');
  const catalogMenu = document.getElementById('catalog-menu');

  catalogBtn.addEventListener('click', function (e) {
    e.preventDefault();

    if (catalogMenu.style.display === 'flex') {
      catalogMenu.style.display = 'none';
      catalogIcon.classList.remove('fa-times');
      catalogIcon.classList.add('fa-bars');
    } else {
      catalogMenu.style.display = 'flex';
      catalogIcon.classList.remove('fa-bars');
      catalogIcon.classList.add('fa-times');
    }
  });


  document.addEventListener('click', function (e) {
    if (
      !catalogMenu.contains(e.target) &&
      !catalogBtn.contains(e.target)
    ) {
      catalogMenu.style.display = 'none';
      catalogIcon.classList.remove('fa-times');
      catalogIcon.classList.add('fa-bars');
    }
  });


// СЛАЙДЕР
const slider = document.getElementById("productSlider");
let scrollAmount = 0;
const cardWidth = 321.5; // карточка + gap (200 + 20)

function scrollSlider(direction) {
  scrollAmount += direction * cardWidth;
  slider.scrollTo({
    left: scrollAmount,
    behavior: "smooth"
  });
}



// ОКНО "ДОБАВИТЬ В КОРЗИНУ"
let currentModal = null;

  function openModal(productId, productName, buttonElement) {
    const modal = document.getElementById('modal');
    const form = document.getElementById('cart-form');
    const title = document.getElementById('modal-title');
    const productIdInput = document.getElementById('modal-product-id');
    let productNameInput = document.getElementById('modal-product-name');


    productIdInput.value = productId;


    if (!productNameInput) {
      productNameInput = document.createElement('input');
      productNameInput.type = 'hidden';
      productNameInput.name = 'product_name';
      productNameInput.id = 'modal-product-name';
      form.appendChild(productNameInput);
    }

    productNameInput.value = productName;


    modal.style.display = 'block';
    modal.style.position = 'absolute';


    const rect = buttonElement.getBoundingClientRect();
    modal.style.top = `${rect.top + window.scrollY - modal.offsetHeight - 10}px`;
    modal.style.left = `${rect.left + window.scrollX - 30}px`;


    currentModal = modal;
  }

  function closeModal() {
    if (currentModal) {
      currentModal.style.display = 'none';
      currentModal = null;
    }
  }

  document.getElementById('cart-form').addEventListener('submit', async function(event) {
    event.preventDefault();

    const form = event.target;
    const quantity = form.quantity.value;
    const productId = form.product_id.value;
    const productName = form.product_name.value;

    try {
      const response = await fetch('/add_to_cart', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          product_id: productId,
          product_name: productName,
          quantity: quantity
        })
      });

      const result = await response.json();

      if (result.success) {
        closeModal();
        showNotification('Товар добавлен в корзину!');
      } else {
        alert(result.message || 'Ошибка при добавлении.');
      }
    } catch (error) {
      alert('Ошибка подключения к серверу.');
      console.error(error);
    }
  });
