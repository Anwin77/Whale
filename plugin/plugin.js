async function scanLink(link) {
    try {
      const response = await fetch('http://localhost:3000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ link })
      });
      if (!response.ok) throw new Error('Scan failed');
      return await response.json();
    } catch (error) {
      return { isPhishing: true, message: 'Error scanning link', platform: 'Web', risk: 'Unknown', source: 'N/A' };
    }
  }
  
  function injectShields() {
    const links = document.querySelectorAll('a[href]');
    links.forEach(async (link) => {
      const shield = document.createElement('span');
      shield.innerHTML = `<svg class="shield w-4 h-4 inline-block ml-1" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 2L3 7v7c0 5 9 9 9 9s9-4 9-9V7l-9-5z" stroke-width="2"/></svg>`;
      shield.style.color = '#6b7280';
      link.appendChild(shield);
  
      const result = await scanLink(link.href);
      shield.style.color = result.isPhishing ? '#ef4444' : '#22c55e';
      shield.title = result.message;
  
      anime({
        targets: shield.querySelector('.shield'),
        scale: [1, 1.2, 1],
        duration: 1000,
        easing: 'easeInOutQuad'
      });
    });
  }
  
  document.addEventListener('DOMContentLoaded', injectShields);