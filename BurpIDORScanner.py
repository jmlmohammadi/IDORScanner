from burp import IBurpExtender, IHttpListener, ITab
from java.net import URL
from javax.swing import JPanel, JLabel, JTextField, JButton, JTable, JScrollPane, DefaultTableModel, JFileChooser, JOptionPane
import re
import csv
import os

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Ultimate IDOR Scanner (Comprehensive)")

        # Register HTTP Listener to intercept requests
        self._callbacks.registerHttpListener(self)

        # Keep track of tested combinations to avoid redundant scanning
        # Key might be (host, path, paramName, originalID, toolFlag)
        self.tested_combos = set()

        #
        # GUI Setup
        #
        self.panel = JPanel()
        self.panel.setLayout(None)

        # Label and text field for custom IDs
        label = JLabel("Custom IDs (comma-separated):")
        label.setBounds(10, 10, 200, 20)
        self.panel.add(label)

        self.id_input = JTextField()
        self.id_input.setBounds(10, 35, 200, 25)
        self.panel.add(self.id_input)

        # Start Scan Button
        self.start_button = JButton("Start IDOR Scan", actionPerformed=self.start_scan)
        self.start_button.setBounds(10, 70, 150, 30)
        self.panel.add(self.start_button)

        # Export Button
        self.export_button = JButton("Export Report", actionPerformed=self.export_report)
        self.export_button.setBounds(170, 70, 150, 30)
        self.panel.add(self.export_button)

        # Results Table
        self.table_model = DefaultTableModel(["URL/Path", "Parameter", "Original ID", "Fuzzed Value", "Status"], 0)
        self.results_table = JTable(self.table_model)
        scroll_pane = JScrollPane(self.results_table)
        scroll_pane.setBounds(10, 110, 700, 300)
        self.panel.add(scroll_pane)

        # Register UI Tab
        self._callbacks.addSuiteTab(self)

        # Log file setup
        self.log_file = os.path.join(os.getcwd(), "Ultimate_IDOR_Results.csv")

        print("[*] Ultimate IDOR Scanner (Comprehensive) Loaded")

    #
    # ITab interface
    #
    def getTabCaption(self):
        return "IDOR Scanner Ultimate"

    def getUiComponent(self):
        return self.panel

    #
    # IHttpListener interface
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Intercept HTTP messages. We only want to process requests after they've been formed.
        We'll parse out all numeric / hashed IDs from path and parameters to fuzz them.
        """
        if not messageIsRequest:
            return

        # Optionally limit to certain tools only (e.g. PROXY, REPEATER, SCANNER, etc.)
        # if toolFlag != self._callbacks.TOOL_PROXY:
        #     return

        # Analyze the request
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl()
        if not url:
            return

        # The service (host, port, protocol) for sending requests
        http_service = messageInfo.getHttpService()

        # Gather potential IDs from the PATH and from QUERY/BODY parameters
        path_ids = self.extract_ids_from_path(url)
        param_ids = self.extract_ids_from_parameters(request_info)

        all_ids_found = path_ids.union(param_ids)
        if not all_ids_found:
            return

        # For each discovered ID, generate fuzz tests
        for (id_type, param_name, original_value) in all_ids_found:
            # Avoid re-testing the exact same scenario
            combo_key = (http_service.getHost(), url.getPath(), param_name, original_value, toolFlag)
            if combo_key in self.tested_combos:
                continue
            self.tested_combos.add(combo_key)

            # Launch IDOR tests
            self.test_idor(messageInfo, request_info, id_type, param_name, original_value)

    #
    # ID Extraction Helpers
    #
    def extract_ids_from_path(self, url_obj):
        """
        Identify numeric or hashed patterns in the URL path segments.
        Return a set of tuples: (id_type, param_name, original_value)
           - id_type might be "path"
           - param_name can be e.g. "path_segment"
           - original_value is the found ID
        """
        results = set()
        path = url_obj.getPath() or ""

        # For numeric IDs
        numeric_matches = re.findall(r'/(\d+)(?=/|$)', path)
        for val in numeric_matches:
            results.add(("path", "path_segment", val))

        # For hashed IDs (32 hex chars for MD5, or 40 for SHA1, etc.)
        hash_matches = re.findall(r'/([a-fA-F0-9]{32,40})(?=/|$)', path)
        for val in hash_matches:
            results.add(("path", "path_segment", val))

        return results

    def extract_ids_from_parameters(self, request_info):
        """
        Use Burp's parameter parsing to find numeric/hashed IDs among query or body parameters.
        Return a set of tuples: (id_type, param_name, original_value)
        """
        results = set()
        params = request_info.getParameters()
        for param in params:
            param_name = param.getName()
            param_value = param.getValue()
            param_type = param.getType()  # QUERY, BODY, COOKIE, etc.

            # Basic numeric detection
            if re.match(r'^\d+$', param_value):
                if param_type == 0:
                    # 0 = QUERY parameter
                    results.add(("query", param_name, param_value))
                elif param_type == 1:
                    # 1 = BODY parameter
                    results.add(("body", param_name, param_value))

            # Basic hashed pattern detection (32 or 40 hex chars => MD5 or SHA1, etc.)
            if re.match(r'^[a-fA-F0-9]{32,40}$', param_value):
                if param_type == 0:
                    results.add(("query", param_name, param_value))
                elif param_type == 1:
                    results.add(("body", param_name, param_value))

        return results

    #
    # Fuzz Logic
    #
    def test_idor(self, messageInfo, request_info, id_type, param_name, original_value):
        """
        For each discovered ID, generate test cases and attempt the IDOR fuzz requests.
        """
        fuzz_cases = self.generate_test_cases(original_value, request_info.getUrl().toString())

        for new_id, payload_label in fuzz_cases:
            # Build a modified request for each fuzz
            new_request = self.build_modified_request(
                messageInfo, request_info, id_type, param_name, original_value, new_id
            )
            if not new_request:
                continue

            # Send request
            http_service = messageInfo.getHttpService()
            response = self._callbacks.makeHttpRequest(http_service, new_request)
            if not response:
                continue

            # Check status code
            analyzed_response = self._helpers.analyzeResponse(response.getResponse())
            status_code = analyzed_response.getStatusCode()

            # If status is 200, assume potential IDOR
            # You can expand checks or parse the response body for more robust detection
            if status_code == 200:
                print(f"[+] Potential IDOR - Param '{param_name}': {original_value} -> {new_id} ({payload_label})")
                messageInfo.setHighlight("red")  # highlight original in proxy/history

                # Insert row in table
                row_data = [
                    request_info.getUrl().getPath(),
                    param_name,
                    original_value,
                    f"{new_id} ({payload_label})",
                    f"{status_code} OK"
                ]
                self.table_model.addRow(row_data)

                # Log result to disk
                self.log_result(request_info.getUrl().toString(), param_name, original_value, new_id, status_code)

    def generate_test_cases(self, original_id, full_url):
        """
        Generate multiple test cases for IDOR fuzzing. 
        You can adapt or expand this as needed.
        """
        # Collect user-specified custom IDs
        custom_input = self.id_input.getText().strip()
        custom_ids_list = [x.strip() for x in custom_input.split(",") if x.strip()] if custom_input else []

        # If none provided, fallback to increment
        if not custom_ids_list:
            if re.match(r'^\d+$', original_id):
                # If numeric, try original+1
                custom_ids_list = [str(int(original_id) + 1)]
            else:
                custom_ids_list = ["1111"]

        fuzz_cases = []
        # 1) Swap with user-supplied custom IDs
        for cid in custom_ids_list:
            fuzz_cases.append((cid, "Custom ID"))

        # 2) A small set of fallback tests
        fuzz_cases += [
            ("*", "Wildcard Injection"),
            ("../" + original_id, "Path Traversal"),
            (original_id + ".json", "File Extension - JSON"),
            (original_id + ".xml", "File Extension - XML"),
            (original_id + ".config", "File Extension - CONFIG"),
            (original_id + ".txt", "File Extension - TXT"),
            (original_id.upper(), "ID Uppercase"),
            (original_id.lower(), "ID Lowercase"),
        ]

        # 3) JSON/parameter pollution style tests
        fuzz_cases += [
            ("{\"userid\":%s,\"userid\":9999}" % original_id, "JSON Parameter Pollution"),
            ("{\"userid\":[%s]}" % original_id, "ID Wrapped in Array"),
            ("{\"userid\":{\"userid\":%s}}" % original_id, "ID Wrapped in Object"),
            (f"user_id={original_id}&user_id=9999", "HTTP Parameter Pollution"),
        ]

        # 4) If we suspect a hashed ID, try small mutation
        if re.match(r'^[a-fA-F0-9]{32,40}$', original_id):
            mutated = original_id[:2] + "fff" + original_id[5:]  # trivial example
            fuzz_cases.append((mutated, "Hash Mutation"))

        # 5) Outdated API version if /v3/ is in the URL
        if "/v3/" in full_url:
            fuzz_cases.append((original_id, "API v3 -> v1 (manual)"))

        return fuzz_cases

    def build_modified_request(self, messageInfo, request_info, id_type, param_name, original_value, new_value):
        """
        Construct a new HTTP request with the ID replaced in either:
          - Path segment
          - Query parameter
          - Body parameter
        We rely on Burp’s buildParameter() to reconstruct query/body parameters, 
        and manual string replacement for path segments.
        """
        # Original request bytes
        req_bytes = messageInfo.getRequest()
        analyzed_req = request_info
        body_offset = analyzed_req.getBodyOffset()
        body_bytes = req_bytes[body_offset:] if body_offset < len(req_bytes) else b''

        # Convert to a modifiable list of headers
        headers = list(analyzed_req.getHeaders())
        # The first header line is something like "GET /path HTTP/1.1"
        request_line = headers[0].split(' ')
        method = request_line[0]
        path_query = request_line[1]
        protocol_version = request_line[2] if len(request_line) > 2 else "HTTP/1.1"

        new_headers = []
        new_body = body_bytes  # default to unchanged

        #
        # CASE 1: If the ID is in the path
        #
        if id_type == "path":
            # example: /users/123 -> /users/999
            new_path = path_query.replace(original_value, new_value, 1)
            # Rebuild first header line
            new_request_line = f"{method} {new_path} {protocol_version}"
            new_headers = [new_request_line] + headers[1:]

        #
        # CASE 2/3: If the ID is in a query or body parameter
        #
        else:
            # Step 1: We want to parse the parameters again, remove the old one, add the new one.
            new_params = []
            for p in analyzed_req.getParameters():
                if p.getName() == param_name and p.getValue() == original_value:
                    # Rebuild parameter with new value
                    new_param = self._helpers.buildParameter(
                        p.getName(),
                        new_value,
                        p.getType()
                    )
                    new_params.append(new_param)
                else:
                    new_params.append(p)

            # Step 2: If any modifications to the path are needed (rare if param is strictly query)
            new_path = path_query  # usually unchanged unless we want to manipulate the path

            # Step 3: Reconstruct the entire request with updated parameters
            # (buildHttpMessage automatically handles query vs body for us if we pass in new parameters)
            # BUT we have to handle the path ourselves in some older Burp APIs, so we'll do manual steps.

            # Clean existing query if method=GET with parameters
            # We’ll just keep the raw path (no ? query) in the first line to let buildHttpMessage do the rest.
            if "?" in new_path:
                new_path = new_path.split("?")[0]

            new_request_line = f"{method} {new_path} {protocol_version}"
            new_headers = [new_request_line] + headers[1:]

            # Build the new HTTP message
            # buildHttpMessage(List<String> headers, byte[] body)
            # buildHttpMessage(List<String> headers, List<IParameter> parameters, byte[] body)
            # The newer API supports parameters, but if not available, we must do it manually.
            # A simpler approach is to rebuild from scratch with setParameters().
            # We'll do a manual approach:

            temp_request = self._helpers.buildHttpMessage(new_headers, b"")  
            temp_request_info = self._helpers.analyzeRequest(temp_request)

            # Start with new_headers and no body
            mod_request = bytearray(temp_request)

            # Add each parameter
            for np in new_params:
                mod_request = self._helpers.updateParameter(mod_request, np)

            # This bytearray is now the final new request
            return bytes(mod_request)

        # If path-based, we just rebuild with new_headers & same body
        return self._helpers.buildHttpMessage(new_headers, new_body)

    #
    # Logging
    #
    def log_result(self, full_url, param_name, old_value, new_value, status_code):
        """
        Log successful IDOR attempts to a CSV file, for persistent records.
        """
        with open(self.log_file, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([full_url, param_name, old_value, new_value, status_code])

    #
    # GUI Actions
    #
    def start_scan(self, event):
        """
        Invoked when 'Start IDOR Scan' is clicked. Right now it’s just a message,
        but you can integrate an active scanning routine if desired.
        """
        JOptionPane.showMessageDialog(
            self.panel,
            "Custom IDOR scanning is active.\n"
            "Requests in various Burp tools will be monitored for IDs."
        )

    def export_report(self, event):
        """
        Export current table results to CSV, matching what's in the GUI table.
        """
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Report")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".csv"):
                file_path += ".csv"

            with open(file_path, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["URL/Path", "Param Name", "Original ID", "Fuzzed Value", "Status"])

                for row in range(self.table_model.getRowCount()):
                    writer.writerow([
                        self.table_model.getValueAt(row, 0),
                        self.table_model.getValueAt(row, 1),
                        self.table_model.getValueAt(row, 2),
                        self.table_model.getValueAt(row, 3),
                        self.table_model.getValueAt(row, 4)
                    ])

            print(f"[+] Report exported to {file_path}")
