const API_BASE = "http://127.0.0.1:5000/api";

const statusBadge = document.getElementById("status-badge");
const alertBanner = document.getElementById("alert-banner");
const statDevices = document.getElementById("stat-devices");
const statFdi = document.getElementById("stat-fdi");
const statCrypto = document.getElementById("stat-crypto");
const statStatus = document.getElementById("stat-status");
const devicesBody = document.getElementById("devices-body");
const alertsBody = document.getElementById("alerts-body");
const btnFdi = document.getElementById("btn-fdi");
const btnTamper = document.getElementById("btn-tamper");

let energyChart;
const maxDataPoints = 20;
let chartLabels = [];
let chartDataNormal = [];
let chartDataAttack = [];

document.addEventListener("DOMContentLoaded", () => {
    initChart();
    fetchHealth();
    fetchDevices();
    fetchDashboard();
    fetchAlerts();

    setInterval(fetchHealth, 10000);
    setInterval(fetchDashboard, 5000);
    setInterval(fetchAlerts, 5000);
    setInterval(simulateChartData, 5000);

    setupButtons();
});

function setupButtons() {
    btnFdi.addEventListener("click", async () => {
        try {
            btnFdi.disabled = true;
            btnFdi.innerText = "Triggering...";
            const res = await fetch(`${API_BASE}/trigger-fdi-attack`);
            if(res.ok) {
                showAlertBanner();
                fetchDashboard();
                fetchAlerts();
            }
        } catch (err) {
            console.error(err);
        } finally {
            btnFdi.disabled = false;
            btnFdi.innerText = "Trigger FDI Attack";
        }
    });

    btnTamper.addEventListener("click", async () => {
        try {
            btnTamper.disabled = true;
            btnTamper.innerText = "Tampering...";
            const res = await fetch(`${API_BASE}/tamper-signature`);
            if(res.ok) {
                fetchDashboard();
                fetchAlerts();
            }
        } catch (err) {
            console.error(err);
        } finally {
            btnTamper.disabled = false;
            btnTamper.innerText = "Trigger Signature Tampering";
        }
    });
}

async function fetchHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        if (data.status === "running") {
            statusBadge.textContent = "Backend Online";
            statusBadge.className = "badge bg-green";
        }
    } catch (err) {
        statusBadge.textContent = "Backend Offline";
        statusBadge.className = "badge bg-red";
    }
}

async function fetchDevices() {
    try {
        const res = await fetch(`${API_BASE}/devices`);
        const devices = await res.json();
        
        devicesBody.innerHTML = "";
        devices.forEach(d => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${d.device_id}</td>
                <td>${d.device_name}</td>
                <td>${d.device_type}</td>
            `;
            devicesBody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load devices", err);
    }
}

async function fetchDashboard() {
    try {
        const res = await fetch(`${API_BASE}/security-dashboard`);
        const stats = await res.json();
        
        statDevices.innerText = stats.total_devices || 0;
        statFdi.innerText = stats.fdi_attacks_detected || 0;
        statCrypto.innerText = stats.crypto_failures || 0;
        
        statStatus.innerText = stats.status || "Unknown";
        if (stats.status === "Secure") {
            statStatus.style.color = "var(--success)";
        } else {
            statStatus.style.color = "var(--danger)";
        }

        if(stats.fdi_attacks_detected > 0) {
           // Original behavior: "System Status under attack all the time" was requested fixed, but the original was just simple.
           // However the actual status logic is computed in the backend now, so we just display the stats.status.
        }

    } catch (err) {
        console.error("Failed to load dashboard stats", err);
    }
}

// Fetch Alerts
async function fetchAlerts() {
    try {
        const res = await fetch(`${API_BASE}/fdi-alerts`);
        const alerts = await res.json();
        
        alertsBody.innerHTML = "";
        alerts.forEach(a => {
            const tr = document.createElement("tr");
            const time = new Date(a.timestamp).toLocaleTimeString();
            
            let severityClass = "";
            let severityText = "UNCOMPROMISED";
            
            if (a.type === "FDI_ATTACK" || a.type === "CRYPTO_ATTACK") {
                severityClass = "severity-high";
                severityText = "HIGH";
            } else {
                // Parse the kWh value to simulate different severities for demo
                const match = a.detail ? a.detail.match(/(\d+(\.\d+)?)/) : null;
                const kwh = match ? parseFloat(match[1]) : 0;
                
                if (kwh > 150) {
                    severityClass = "severity-medium";
                    severityText = "MEDIUM";
                } else if (kwh > 100) {
                    severityClass = "severity-low";
                    severityText = "LOW";
                } else {
                    severityClass = "severity-uncompromised";
                    severityText = "UNCOMPROMISED";
                }
            }
            
            tr.innerHTML = `
                <td>${a.device_id}</td>
                <td>${time}</td>
                <td class="${severityClass}">${severityText}</td>
                <td>${a.detail || a.detection_reason}</td>
            `;
            alertsBody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load alerts", err);
    }
}

function showAlertBanner() {
    alertBanner.classList.remove("hidden");
    alertBanner.classList.add("flash");
    setTimeout(() => {
        alertBanner.classList.add("hidden");
        alertBanner.classList.remove("flash");
    }, 5000);
}

function initChart() {
    const ctx = document.getElementById('energyChart').getContext('2d');
    
    for(let i=0; i<maxDataPoints; i++) {
        chartLabels.push('');
        chartDataNormal.push(null);
        chartDataAttack.push(null);
    }

    energyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [
                {
                    label: 'Normal Consumption (kWh)',
                    data: chartDataNormal,
                    borderColor: '#38bdf8',
                    backgroundColor: 'rgba(56, 189, 248, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'FDI Anomalies (kWh)',
                    data: chartDataAttack,
                    borderColor: '#ef4444',
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    pointBackgroundColor: '#ef4444',
                    pointRadius: 5,
                    showLine: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 400,
                easing: 'linear'
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: '#334155' },
                    ticks: { color: '#94a3b8' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#f8fafc' }
                }
            }
        }
    });
}

function simulateChartData() {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: "numeric", minute: "numeric", second: "numeric" });
    
    chartLabels.push(time);
    chartLabels.shift();
    
    const normalVal = 30 + (Math.random() * 20);
    
    chartDataNormal.push(normalVal);
    chartDataNormal.shift();

    if (!alertBanner.classList.contains("hidden")) {
        chartDataAttack.push(normalVal * (3 + Math.random()));
    } else {
        chartDataAttack.push(null);
    }
    chartDataAttack.shift();

    energyChart.update('none');
}
