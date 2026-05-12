const username = localStorage.getItem('user') || 'Pengguna';

const navbar = document.getElementById('navbar');
if (navbar) {
  navbar.innerHTML = `
    <div class="navbar">
      <div style="display: flex; gap: 1rem; align-items: center;">
        <a href="dashboard.html">🏠 Beranda</a>

        <div class="dropdown">
          <button class="dropbtn">📤 Surat Keluar ▼</button>
          <div class="dropdown-content">
            <a href="surat-keluar.html">📝 Form Surat Keluar</a>
            <a href="data-surat-keluar.html">📑 Data Surat Keluar</a>
          </div>
        </div>

        <div class="dropdown">
          <button class="dropbtn">📥 Surat Masuk ▼</button>
          <div class="dropdown-content">
            <a href="surat-masuk.html">📝 Form Surat Masuk</a>
            <a href="data-surat-masuk.html">📬 Data Surat Masuk</a>
          </div>
        </div>
      </div>

      <div style="color: #f2f2f2; margin-left: auto; display: flex; align-items: center; gap: 1rem;">
        👤 <strong>${username}</strong>
        <a href="index.html" onclick="logout()">🚪 Keluar</a>
      </div>
    </div>
  `;
}

function logout() {
  localStorage.removeItem('user');
  window.location.href = 'index.html';
}
