// HTML template for the form
const formHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Data Form</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        form { margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
          .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
        }
        textarea {
            width: 100%;
            min-height: 150px;
            padding: 0.5rem;
        }
        select, input[type="text"] {
            width: 100%;
            padding: 0.5rem;
        }
        button {
            background: #0066cc;
            color: white;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h2>The Phishers Collective</h2>
    Phishing is a real threat. Let us worry about it and investigate the link and sources by submitting the phishing message you received.
    Read more here at <a href="https://kalsec.notion.site/The-Phishers-Collective-13c4fb26a3f3800ab408ca2a2c012c85">The Phishes Collective - KalSec</a>

    <h3>Please submit the info of suspected phishing link you received.</h3>

    <form method="POST">

     <div class="form-group">
            <label for="phishing_text">Phishing Text [Required]</label>
            <textarea id="phishing_text" name="phishing_text" required></textarea>
        </div>

        <div class="form-group">
            <label for="extracted_url">Extracted URL [Optional]</label>
            <input type="text" id="extracted_url" name="extracted_url" placeholder="Be careful while clicking or copying">
        </div>

        <div class="form-group">
            <label for="received_via">Received Via</label>
            <select id="received_via" name="received_via" required>
                <option value="">Select channel</option>
                <option value="email">Email</option>
                <option value="sms">SMS</option>
                <option value="whatsapp">WhatsApp</option>
                <option value="other">Other</option>
            </select>
        </div>

        <div class="form-group">
            <label for="device">Device</label>
            <select id="device" name="device">
                <option value="Unspecified">Select device</option>
                <option value="mobile">Mobile</option>
                <option value="desktop">Desktop</option>
                <option value="tablet">Tablet</option>
            </select>
        </div>

        <div class="form-group">
            <label for="device_brand">Device Brand [Optional]</label>
            <input type="text" id="device_brand" name="device_brand" placeholder="Unspecified">
        </div>

        <button type="submit">Submit</button>
    </form>
    {{TABLE_CONTENT}}
</body>
</html>
`;

// Function to generate table HTML from data
function generateTableHTML(data) {
  if (data.length === 0) return "<p>No submissions yet.</p>";

  let tableHTML = `
  <h2>Phishing Submissions</h2>
  <style>
      table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 20px;
      }
      th, td {
          border: 1px solid #ddd;
          padding: 8px;
          text-align: left;
      }
      th {
          background-color: #f2f2f2;
      }
      tr:nth-child(even) {
          background-color: #f9f9f9;
      }
  </style>
  <table>
      <tr>
          <th>ID</th>
          <th>Phishing Text</th>
          <th>Extracted URL</th>
          <th>Received Via</th>
          <th>Device</th>
          <th>Device Brand</th>
      </tr>
  `;

  data.forEach((row) => {
    tableHTML += `
        <tr>
            <td>${row.id}</td>
            <td>${row.phishing_text}</td>
            <td>${row.extracted_url}</td>
            <td>${row.received_via}</td>
            <td>${row.device}</td>
            <td>${row.device_brand}</td>
        </tr>
    `;
  });

  tableHTML += `</table>`;
  return tableHTML;
}

export default {
  async fetch(request, env) {
    // Handle different HTTP methods
    switch (request.method) {
      case "POST":
        return handlePost(request, env);
      case "GET":
        return handleGet(request, env);
      default:
        return new Response("Method not allowed", { status: 405 });
    }
  },
};

async function handleGet(request, env) {
  // Fetch all submissions from the database
  const { results } = await env.DB.prepare(
    "SELECT * FROM phishes ORDER BY created_at DESC",
  ).all();

  // Generate the complete HTML with the table
  const html = formHTML.replace(
    "{{TABLE_CONTENT}}",
    generateTableHTML(results),
  );

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}

// Helper function to defang URLs
function defangUrl(text) {
  if (!text) return text;
  const urlRegex = /(https?:\/\/[^\s]+)/gi;
  return text.replace(urlRegex, "{$1}");
}

async function handlePost(req, env) {
  const formData = await req.formData();
  const headers = Object.fromEntries(req.headers);

  // Extract phishing form data
  const phishingText = defangUrl(formData.get("phishing_text"));
  const extractedUrl =
    defangUrl(formData.get("extracted_url")) || "Unextracted";
  const receivedVia = formData.get("received_via");
  const device = formData.get("device") || "Unspecified";
  const deviceBrand = formData.get("device_brand") || "Unspecified";

  // System collected data
  const userAgent = headers["user-agent"] || "N/A";
  const allHttpHeaders = JSON.stringify(headers) || "N/A";
  const cfRequestHeaders = JSON.stringify(req.headers) || "N/A";
  const ip = JSON.stringify(req.headers.get("cf-connecting-ip")) || "Unknown";
  const createdAt = new Date().toISOString();

  // Get current timestamp
  const timestamp = new Date().toISOString();

  // Insert data into database
  await env.DB.prepare(
    `
      INSERT INTO phishes (
          phishing_text,
          extracted_url,
          received_via,
          device,
          device_brand,
          user_agent,
          all_http_headers,
          cf_request_headers,
          ip,
          created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `,
  )
    .bind(
      phishingText,
      extractedUrl,
      receivedVia,
      device,
      deviceBrand,
      userAgent,
      allHttpHeaders,
      cfRequestHeaders,
      ip,
      createdAt,
    )
    .run();

  // Redirect back to GET to show the updated list
  return Response.redirect(req.url, 302);
}
