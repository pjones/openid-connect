// Initiate a WebSocket connection to the backend
const ws = new WebSocket(`wss://${window.location.host}/wait_for_login`);

ws.onopen = () => console.log('WebSocket connection established');
ws.onerror = (error) => console.error('WebSocket error:', error);
ws.onclose = (event) => console.log('WebSocket connection closed:', event);

// Receive data from the backend
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  // Receive an ID for the WebSocket connection, and store it in a session cookie
  if (data.hasOwnProperty('socketID')) {
    document.cookie = `socketID=${data.socketID}; path=/`;
  }

  // Receive acccess tokens and possibly name+picture of logged in user, and
  // display them
  else if (data.hasOwnProperty('access_tokens')) {
    document.getElementById("tokens").textContent = "Your tokens: " +
      JSON.stringify(data, null, 2);
    if (data.hasOwnProperty('id_token')) {
      document.getElementById("login").textContent = "Logged in as " +
        data.id_token.name;
      document.getElementById("pic").innerHTML =
        `<img src="${data.id_token.picture}" width="32" height="32">`;
    } else {
      // Name not available
      document.getElementById("login").textContent = "Logged in"
    }
  }

  else {
    console.log('Received message:', data);
  }
};