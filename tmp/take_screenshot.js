const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch({args: ['--no-sandbox', '--disable-setuid-sandbox']});
  const page = await browser.newPage();
  await page.goto('http://localhost:3000');
  
  // Actually wait for elements
  await page.waitForSelector('#loginUsername');
  
  // Log in with ITinfra / (whatever password - actually, I don't know the password. Let's just bypass auth for the screenshot?)
  // Let me look at index.html, if it's already logged in, the terminal shows.
  // We can just use page.evaluate to trigger connectToServer directly if we mock currentUser.
  
  await page.evaluate(() => {
    window.currentUser = { username: 'ITinfra', group: 'ITinfra', assignedServers: [] };
    window.discoveredLogs = [];
    window.serversCache = [{ id: 'TEST-SRV', host: 'localhost', user: 'root' }];
    
    // We can just hide login and show main
    document.getElementById('loginModal').style.display = 'none';
    
    // Create a mock server element
    const list = document.getElementById('serverList');
    const item = document.createElement('div');
    item.className = 'server-item';
    item.innerHTML = '<div class="server-info"><span class="server-name">TEST-SRV</span></div>';
    list.appendChild(item);
    
    // Call connectToServer
    connectToServer('TEST-SRV', item, { id: 'TEST-SRV', group: 'Test', host: 'localhost' });
  });

  await new Promise(r => setTimeout(r, 2000)); //(2000);
  await page.screenshot({path: 'tmp/terminal_mocked.png'});
  await browser.close();
})();
