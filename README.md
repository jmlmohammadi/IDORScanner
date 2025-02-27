# Ultimate IDOR Scanner - Extended

An advanced **Burp Suite extension** for detecting and exploiting Insecure Direct Object References (IDOR) and related access control flaws. The extension identifies numeric or hashed IDs in paths, parameters, and JSON bodies, then **fuzzes** them with various techniques—such as increments, path traversal, parameter pollution, or HTTP method overrides—to reveal potential vulnerabilities.

## Features

1. **Path, Query, and Body Parameter Detection**  
   - Extracts IDs from URL paths, standard parameters, and JSON/XML-like bodies (JSON requires Python/Jython’s `json` library).

2. **Advanced JSON Parsing**  
   - Parses nested objects/arrays to locate IDs (for example, in `{"profile": {"id": 123}}`).  
   - Replaces those IDs with fuzzed values.

3. **Method Overrides**  
   - Optionally re-sends requests using `PUT`, `DELETE`, or other HTTP methods to test for hidden endpoints or privileged actions.

4. **Custom & Dictionary-Based IDs**  
   - Merges user-supplied IDs (from a text field in the UI) with an external dictionary file (e.g., `dictionary_ids.txt`) for large-scale fuzzing.

5. **Parameter Name Tampering**  
   - Adds certain strings (like `;admin=true`) or modifies uppercase/lowercase to detect more nuanced access control bypasses.

6. **Concurrency Option**  
   - Allows background threading to avoid blocking Burp while sending multiple fuzzed requests.

7. **Baseline Comparison**  
   - Captures the **original** response status/length, then compares each fuzzed request for interesting differences (e.g., a `403 -> 200` transition).

8. **GUI Table and CSV Logging**  
   - Displays discovered potential IDORs in a GUI table on a custom **Suite** tab.  
   - Logs results to `Ultimate_IDOR_Results.csv` and supports easy CSV export.

## Requirements

- **Burp Suite** (Professional or Community Edition)  
- **Jython** 2.7+ (or a compatible JRE-based Python environment) if you want JSON parsing.  
- A **Java 8+** environment for running Burp.

> **Note**: JSON parsing relies on `json` from the Jython standard library. If your Jython distribution doesn’t have it, you may need to install or bundle a JSON library.

## Installation

1. **Clone / Download** this repository:
   ```bash
   git clone https://github.com/<YourUsername>/Ultimate-IDOR-Scanner-Extended.git
   ```
2. **Compile / Package** (if needed). Usually, you can load `.py` extensions directly into Burp if you have Jython set up:
   - Place the `.py` file in a location that Burp can read.
3. **Configure Jython in Burp**:
   - In **Burp Suite** → **Extender** → **Options** → **Python Environment**,  
   - Point to the `jython.jar` location.
4. **Load the Extension**:
   - In **Burp Suite** → **Extender** → **Extensions** → **Add** → Select **Extension type** = Python,  
   - Browse to your `Ultimate_IDOR_Scanner_Extended.py` file and click **Next** / **Done**.

Once loaded, you should see a success message in **Burp’s Extender** tab console:  
```
[*] Ultimate IDOR Scanner (Extended) Loaded
```

## Usage

1. **Open the “IDOR Scanner Ultimate” Tab**  
   - You’ll see the following UI elements:
     - A text field for **Custom IDs** (comma-separated).  
     - A checkbox to **Enable background concurrency**.  
     - A **Start IDOR Scan** button.  
     - An **Export Report** button.  
     - A results table where discovered vulnerabilities appear.

2. **Optional**: Add **Custom IDs** in the text field (e.g., `101, 9999`).

3. **Concurrency**:
   - Check the box if you want to run IDOR tests in separate threads. This helps keep Burp responsive during large scans but can make traffic heavier.

4. **Start IDOR Scan**:
   - Click the button (it shows a message). By default, the extension immediately analyzes any new requests passing through **Proxy**, **Repeater**, etc.

5. **Interact with Your Target**:
   - Browse or send requests through Burp.  
   - The extension intercepts each request, extracts path and parameter IDs, and automatically tries multiple fuzz variations.  
   - If a **200 OK** or suspiciously different response is found, the extension flags it as a **potential IDOR**.

6. **View and Export Results**:
   - **Table**: The extension populates a new row for each potential finding:  
     - *URL/Path*, *Parameter*, *Original ID*, *Fuzzed Value*, *Status*  
   - **Export**: Click **Export Report** to save your table data as CSV.  
   - The extension also automatically appends **log entries** to `Ultimate_IDOR_Results.csv` in your working directory.

## Contributing

1. Fork the repository and make your changes.  
2. Submit a Pull Request with clear explanations of what you changed and why.

## License & Disclaimer

- This extension is provided **as is**, without any warranty. Use it at your own risk and only with explicit permission on applications you own or are authorized to test.  
- Licensed under the [MIT License](https://opensource.org/licenses/MIT) (or choose whichever license you prefer).

---

**Enjoy discovering IDOR vulnerabilities with the Ultimate IDOR Scanner – Extended!** If you have any questions or suggestions, feel free to open an issue or pull request.
