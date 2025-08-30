function formatUTCtoLocal(utcString) {
  if (!utcString) return "";
  // Handle both ISO and MySQL datetime formats
  let dateString = utcString;
  if (!dateString.includes('T')) {
    dateString = dateString.replace(' ', 'T');
  }
  if (!dateString.endsWith('Z')) {
    dateString += 'Z';
  }
  const date = new Date(dateString);
  return isNaN(date.getTime()) ? "Invalid Date" : date.toLocaleString();
}

// ================= Input Validation & Error Handling for All Forms =================
function validateEmail(email) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
}
function validatePassword(password) {
  return password.length >= 8 && /[A-Z]/.test(password) && /[0-9]/.test(password);
}
function validateSoilInputs(data) {
  return (
    data.N >= 0 && data.P >= 0 && data.K >= 0 &&
    data.temperature >= -20 && data.temperature <= 60 &&
    data.humidity >= 0 && data.humidity <= 100 &&
    data.ph >= 0 && data.ph <= 14 &&
    data.rainfall >= 0
  );
}

// === JWT Fetch Wrapper ===
async function apiFetch(url, options = {}) {
  const token = localStorage.getItem("accessToken");
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    options.headers || {},
    token ? { Authorization: `Bearer ${token}` } : {}
  );

  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      const retryHeaders = Object.assign(
        { "Content-Type": "application/json" },
        options.headers || {},
        { Authorization: `Bearer ${localStorage.getItem("accessToken")}` }
      );
      return fetch(url, { ...options, headers: retryHeaders });
    }
  }
  return res;
}

async function tryRefresh() {
  const rt = localStorage.getItem("refreshToken");
  if (!rt) return false;
  const res = await fetch("http://127.0.0.1:5000/token/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${rt}` },
  });
  if (!res.ok) return false;
  const data = await res.json();
  if (data.access_token) {
    localStorage.setItem("accessToken", data.access_token);
    return true;
  }
  return false;
}



// Menu functionality
const menuIcon = document.getElementById("menu-icon");
const sidebar = document.getElementById("sidebar");
const overlay = document.getElementById("overlay");
const main = document.querySelector(".main");

function toggleMenu() {
  if (menuIcon && sidebar && main) {
    menuIcon.classList.toggle("active");
    sidebar.classList.toggle("hidden");
    main.classList.toggle("expanded");

    // For mobile, also toggle active class and overlay
    if (window.innerWidth <= 768) {
      sidebar.classList.toggle("active");
      if (overlay) overlay.classList.toggle("active");
    }
  }
}

function closeMenu() {
  if (menuIcon && sidebar && overlay) {
    menuIcon.classList.remove("active");
    sidebar.classList.remove("active");
    overlay.classList.remove("active");

    // For desktop, ensure proper classes
    if (window.innerWidth > 768 && main) {
      sidebar.classList.add("hidden");
      main.classList.add("expanded");
    }
  }
}

// Menu icon click
if (menuIcon) {
  menuIcon.addEventListener("click", toggleMenu);
}

// Overlay click to close menu
if (overlay) {
  overlay.addEventListener("click", closeMenu);
}

// Close menu when clicking on sidebar links (mobile)
if (sidebar) {
  const sidebarLinks = sidebar.querySelectorAll("a");
  sidebarLinks.forEach((link) => {
    link.addEventListener("click", closeMenu);
  });
}

// ML Crop Estimation using Flask API
const soilForm = document.getElementById("soilForm");
if (soilForm) {
  soilForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const user_id = localStorage.getItem("user_id");
    const data = {
      user_id: user_id,
      N: parseFloat(document.getElementById("N").value),
      P: parseFloat(document.getElementById("P").value),
      K: parseFloat(document.getElementById("K").value),
      temperature: parseFloat(document.getElementById("temperature").value),
      humidity: parseFloat(document.getElementById("humidity").value),
      ph: parseFloat(document.getElementById("ph").value),
      rainfall: parseFloat(document.getElementById("rainfall").value),
    };

    apiFetch("http://127.0.0.1:5000/predict", {
  method: "POST",
  body: JSON.stringify(data),
})

      .then((res) => res.json())
      .then((pred) => {
        const results = document.getElementById("results");
        results.innerHTML = `
          <h3>Recommended Crops</h3>
          <div class="result-box"><b>🌾 Random Forest:</b> ${pred.random_forest}</div>
          <div class="result-box"><b>🌳 Decision Tree:</b> ${pred.decision_tree}</div>
          <div class="result-box"><b>🧠 SVM:</b> ${pred.svm}</div>
          <br/>
          <div><small><b>Accuracy:</b> RF: ${pred.accuracies.random_forest}% | DT: ${pred.accuracies.decision_tree}% | SVM: ${pred.accuracies.svm}%</small></div>
        `;

        // Save to localStorage history (⚠️ changed here to use UTC -> local conversion)
        let history = JSON.parse(localStorage.getItem("cropHistory")) || [];

        history.push({
          date: new Date().toISOString(),  // store UTC
          inputs: data,
          predictions: pred,
        });

        localStorage.setItem("cropHistory", JSON.stringify(history));
      })
      .catch((err) => {
        alert("❌ Prediction failed. See console.");
        console.error(err);
      });
  });
}

// Forgot Password Form
const forgotPasswordForm = document.getElementById("forgotPasswordForm");
if (forgotPasswordForm) {
  forgotPasswordForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const email = document.getElementById("email").value;
    const newPassword = prompt("Enter your new password:");
    if (!newPassword) {
      alert("Password reset cancelled.");
      return;
    }
    if (!validatePassword(newPassword)) {
      alert("Password must be at least 8 characters, include a number and an uppercase letter.");
      return;
    }
    fetch("http://127.0.0.1:5000/reset_password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, new_password: newPassword })
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          alert("❌ " + data.error);
        } else {
          alert("✅ Password reset successful!");
          window.location.href = "signin.html";
        }
      })
      .catch((err) => {
        alert("❌ Password reset failed. See console.");
        console.error(err);
      });
  });
}

// Reset Password Form
const resetPasswordForm = document.getElementById("resetPasswordForm");
if (resetPasswordForm) {
  resetPasswordForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    if (!validatePassword(newPassword)) {
      alert("Password must be at least 8 characters, include a number and an uppercase letter.");
      return;
    }
    if (newPassword !== confirmPassword) {
      alert("Passwords do not match!");
      return;
    }
    alert("Password updated successfully!");
    window.location.href = "signin.html";
  });
}

// ================= Register Form Logic =================
const registerForm = document.getElementById("registerForm");

if (registerForm) {
  registerForm.addEventListener("submit", function (e) {
    e.preventDefault();

    const fullName = document.getElementById("fullName").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    if (password !== confirmPassword) {
      alert("❌ Passwords do not match!");
      return;
    }

    fetch("http://127.0.0.1:5000/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fullName, email, password })
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          alert("❌ " + data.error);
        } else {
          alert("✅ Account created successfully!");
          window.location.href = "signin.html";
        }
      })
      .catch((err) => {
        alert("❌ Registration failed. See console.");
        console.error(err);
      });
  });
}

// ================= Sign In Form Logic =================
const signInForm = document.getElementById("signInForm");

if (signInForm) {
  signInForm.addEventListener("submit", function (e) {
    e.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    fetch("http://127.0.0.1:5000/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    })
      .then((res) => res.json())
      .then((data) => {
        if (!data || data.error || !data.error) {
          alert("❌ login failed "+(data.error || data.message || "Unknown error"));
          return;
        } else {
          alert("✅ Sign in successful!");
          localStorage.setItem("accessToken", data.access_token);
          localStorage.setItem("refreshToken", data.refresh_token);
          localStorage.setItem("user_email", data.user.email);
          localStorage.setItem("full_name", data.user.full_name);
          localStorage.setItem("is_admin", data.user.is_admin ? "1" : "0");
          window.location.href = "dashboard.html";
        }
      })
      .catch((err) => {
        alert("❌ Login failed. See console.");
        console.error(err);
      });
  });
}

// ================= Sign Out Logic (signout.html) =================
if (window.location.pathname.includes("admin.html")) {
  const isLoggedIn = localStorage.getItem("isLoggedIn");
  if (isLoggedIn === "true") {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("user_id");
    localStorage.removeItem("full_name");
    alert("✅ You have been signed out.");
  }
}

// ================= Dashboard Access Control =================
if (window.location.pathname.includes("dashboard.html")) {
  const isLoggedIn = localStorage.getItem("isLoggedIn");
  if (isLoggedIn !== "true") {
    alert("⛔ You must log in first.");
    window.location.href = "signin.html";
  }
}

// Always show history on history.html
if (window.location.pathname.includes("history.html")) {
  showUserHistory();
  showLocalStorageHistory(); // Also show localStorage history for reference
}

// ================= User-Specific Prediction History from Backend =================
function showUserHistory() {
  const user_id = localStorage.getItem("user_id");
  const historyDiv = document.getElementById("history");
  if (!historyDiv || !user_id) return;

  apiFetch(`http://127.0.0.1:5000/history/${user_id}`)
    .then(res => res.json())
    .then(data => {
      historyDiv.innerHTML = "<h3>Prediction History (Database)</h3>";
      if (!data || data.length === 0) {
        historyDiv.innerHTML += '<div class="result-box">No prediction history found in database.</div>';
        return;
      }
      data.forEach((entry) => {
        const block = document.createElement("div");
        block.className = "result-box";
        block.innerHTML = `
          <strong>${formatUTCtoLocal(entry.created_at)}</strong><br/>
          <b>Inputs:</b> N=${entry.nitrogen}, P=${entry.phosphorus}, K=${entry.potassium}, Temp=${entry.temperature}°C, Humidity=${entry.humidity}%, pH=${entry.ph}, Rainfall=${entry.rainfall} mm<br/>
          <b>Predicted Crop:</b> ${entry.predicted_crop}
        `;
        historyDiv.appendChild(block);
      });
    })
    .catch((err) => {
      historyDiv.innerHTML += '<div class="result-box">Error loading database history.</div>';
      console.error(err);
    });
}

// ================= Prediction History =================
function showHistory() {
  const historyData = JSON.parse(localStorage.getItem("cropHistory")) || [];
  const historyDiv = document.getElementById("history");
  if (!historyDiv) return;

  historyDiv.innerHTML = "<h3>Prediction History</h3>";
  if (historyData.length === 0) {
    historyDiv.innerHTML +=
      '<div class="result-box">No prediction history found.</div>';
    return;
  }
  historyData
    .slice(-10)
    .reverse()
    .forEach((entry) => {
      const block = document.createElement("div");
      block.className = "result-box";
      block.innerHTML = `
      <strong>${formatUTCtoLocal(entry.date)}</strong><br/>
      <b>Inputs:</b> N=${entry.inputs.N}, P=${entry.inputs.P}, K=${entry.inputs.K}, Temp=${entry.inputs.temperature}°C, Humidity=${entry.inputs.humidity}%, pH=${entry.inputs.ph}, Rainfall=${entry.inputs.rainfall} mm<br/>
      <b>RF:</b> ${entry.predictions.random_forest}, <b>DT:</b> ${entry.predictions.decision_tree}, <b>SVM:</b> ${entry.predictions.svm}
    `;
      historyDiv.appendChild(block);
    });
}

// ================= Show Localstorage History =================
function showLocalStorageHistory() {
  const historyData = JSON.parse(localStorage.getItem("cropHistory")) || [];
  const historyDiv = document.getElementById("history");
  if (!historyDiv) return;

  historyDiv.innerHTML += "<h3>LocalStorage Prediction History</h3>";
  if (historyData.length === 0) {
    historyDiv.innerHTML += '<div class="result-box">No localStorage history found.</div>';
    return;
  }
  historyData
    .slice(-10)
    .reverse()
    .forEach((entry) => {
      const block = document.createElement("div");
      block.className = "result-box";
      block.innerHTML = `
      <strong>${formatUTCtoLocal(entry.date)}</strong><br/>
      <b>Inputs:</b> N=${entry.inputs.N}, P=${entry.inputs.P}, K=${entry.inputs.K}, Temp=${entry.inputs.temperature}°C, Humidity=${entry.inputs.humidity}%, pH=${entry.inputs.ph}, Rainfall=${entry.inputs.rainfall} mm<br/>
      <b>RF:</b> ${entry.predictions.random_forest}, <b>DT:</b> ${entry.predictions.decision_tree}, <b>SVM:</b> ${entry.predictions.svm}
    `;
      historyDiv.appendChild(block);
    });
}

// Profile Update Form
const profileForm = document.getElementById("profileForm");
if (profileForm) {
  profileForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const fullName = document.getElementById("fullName").value;
    const email = document.getElementById("email").value;
    const user_id = localStorage.getItem("user_id");
    fetch("http://127.0.0.1:5000/update_profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id, full_name: fullName, email })
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          alert("❌ " + data.error);
        } else {
          alert("✅ Profile updated successfully!");
          localStorage.setItem("full_name", fullName);
          localStorage.setItem("user_email", email);
        }
      })
      .catch((err) => {
        alert("❌ Profile update failed. See console.");
        console.error(err);
      });
  });
}
