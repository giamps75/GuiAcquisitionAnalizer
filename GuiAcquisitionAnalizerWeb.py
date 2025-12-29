# -*- coding: utf-8 -*-
import streamlit as st
import zipfile
import os
import re
import io
import time
import matplotlib.pyplot as plt

# --- CONFIGURAZIONE PAGINA ---
st.set_page_config(page_title="Gui Analizer 001", layout="wide")

# --- CLASSE DI ANALISI LOGICA (Adattata per Web) ---
class OmniLogAnalyzerWeb:
    def __init__(self):
        self.extracted_data = []
        self.output_files = {}  # Dizionario per salvare i file in memoria: {'nomefile': contenuto}
        self.output1_lines_count = 0

    def run_analysis(self, uploaded_file, custom_api, custom_op, file_type_hint):
        # Reset
        self.extracted_data = []
        self.output_files = {}
        self.output1_lines_count = 0
        
        # Buffer per output1 e output2 (scrittura in memoria)
        out1_buffer = io.StringIO()
        out2_buffer = io.StringIO()

        filename = uploaded_file.name.lower()
        
        try:
            # --- 1. PARSING ---
            if filename.endswith(".mac"):
                self.parse_mac(uploaded_file, custom_api, custom_op, out1_buffer, out2_buffer)
            elif filename.endswith(".csv"):
                # Streamlit uploaded_file è bytes, dobbiamo decodificarlo
                string_io = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="ignore"))
                self.process_standard_logic(string_io, custom_api, custom_op, out1_buffer, out2_buffer)
            elif filename.endswith(".txt"):
                string_io = io.StringIO(uploaded_file.getvalue().decode("utf-8", errors="ignore"))
                self.parse_wmsp(string_io, custom_api, custom_op, out1_buffer, out2_buffer)
            else:
                st.error("File type not supported.")
                return False

            # Salvataggio buffer nei file finali
            self.output_files["output1.txt"] = out1_buffer.getvalue()
            self.output_files["output2.txt"] = out2_buffer.getvalue()

            if not self.extracted_data:
                st.error("No valid data extracted.")
                return False

            # --- 2. ANALISI AUTOMATIZZATA ---
            self.analyze_counters()      # Output 3, 4
            self.analyze_api13()         # Output 5
            self.analyze_api221()        # Output 6
            self.analyze_api9()          # Output 7
            self.analyze_api11_op3()     # Output 8

            return True

        except Exception as e:
            st.error(f"Critical Error: {e}")
            return False

    # --- LOGICHE DI PARSING ---

    def parse_mac(self, uploaded_file, c_api, c_op, out1, out2):
        with zipfile.ZipFile(uploaded_file) as z:
            target = next((f for f in z.namelist() if f.endswith("_WinBusLogContext.txt")), None)
            if target:
                with z.open(target) as f:
                    # Decodifica bytes -> stringa per processarla
                    content = io.StringIO(f.read().decode("utf-8", errors="ignore"))
                    self.process_standard_logic(content, c_api, c_op, out1, out2)
            else:
                st.warning("No valid log context file found in archive.")

    def process_standard_logic(self, file_object, c_api, c_op, out1, out2):
        regex_ts = re.compile(r'^(\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}\.\d+,)\s*')
        
        for line in file_object:
            match = regex_ts.match(line)
            if not match: continue
            
            full_ts = match.group(1)
            data_str = full_ts.rstrip(", ")
            
            riga_nuda = line[len(full_ts):].strip()
            parts = [p.strip() for p in riga_nuda.split(',')]
            
            if len(parts) >= 8:
                source = parts[0]
                # dest = parts[1]
                api = parts[6].upper()
                opcode = parts[7].upper()
                payload_raw = parts[8:]
                payload_str = ".".join(payload_raw)
                
                out1.write(riga_nuda + "\n")
                self.output1_lines_count += 1

                self.extracted_data.append({
                    'data': data_str, 'source': source, 'api': api, 'opcode': opcode, 'payload': payload_str
                })
                
                if c_api and c_op and api.lstrip('0') == c_api.lstrip('0') and opcode.lstrip('0') == c_op.lstrip('0'):
                    out2.write(f"{data_str} - {payload_str}\n")

    def parse_wmsp(self, file_object, c_api, c_op, out1, out2):
        line_idx = 0
        for line in file_object:
            line_idx += 1
            clean = line.strip()
            if not clean: continue
            if clean.startswith(">>"): clean = clean[2:].strip()
            elif clean.startswith(" "): clean = clean.strip()
            
            clean = re.sub(r'[^0-9a-fA-F\s]', '', clean)
            hex_bytes = clean.split()
            
            if len(hex_bytes) > 5 and hex_bytes[5].lower() == "20":
                valid_bytes = hex_bytes[6:]
                if not valid_bytes: continue

                head_str = ".".join(valid_bytes[:3])
                tail_str = ",".join(valid_bytes[3:])
                formatted = head_str + ("," + tail_str if tail_str else "")
                
                out1.write(formatted + "\n")
                self.output1_lines_count += 1

                if len(valid_bytes) >= 4:
                    src = valid_bytes[0].upper()
                    api = valid_bytes[2].upper()
                    opcode = valid_bytes[3].upper()
                    payload_list = valid_bytes[4:]
                    payload_str = ".".join(payload_list)
                    data_str = f"Line_{line_idx}"

                    self.extracted_data.append({
                        'data': data_str, 'source': src, 'api': api, 'opcode': opcode, 'payload': payload_str
                    })
                    
                    if c_api and c_op and api.lstrip('0') == c_api.lstrip('0') and opcode.lstrip('0') == c_op.lstrip('0'):
                        out2.write(f"{data_str} - {payload_str}\n")

    # --- ANALISI SPECIFICHE ---

    def analyze_counters(self):
        self.check_single_counter("0", "output3.txt", "CounterSource0") 
        self.check_single_counter("1", "output4.txt", "CounterSource1")

    def check_single_counter(self, src_target, filename, label):
        filtered = [d for d in self.extracted_data 
                    if d['api'].lstrip('0') == "20" and d['opcode'].lstrip('0') == "2" 
                    and d['source'].lstrip('0') == src_target.lstrip('0')]

        errors = []
        output_lines = []
        last_val = None

        for d in filtered:
            payload_txt = d['payload']
            output_lines.append(f"{d['data']}; {d['api']}; {d['opcode']}; {payload_txt}")
            try:
                if not payload_txt: continue
                first_byte = int(payload_txt.split('.')[0], 16)
                if last_val is not None:
                    if first_byte != (last_val + 1) % 256:
                        errors.append(f"{d['data']}; {d['api']}; {d['opcode']}; {payload_txt}")
                last_val = first_byte
            except: continue

        buffer = io.StringIO()
        for l in output_lines: buffer.write(l + "\n")
        buffer.write("\n--- REPORT ---\n")
        
        if not errors and filtered: buffer.write(f"{label} sequence valid (Always incremented correctly).\n")
        elif not errors and not filtered: buffer.write(f"No data found for {label}.\n")
        else:
            buffer.write(f"Errors found for {label} (Not incremented correctly):\n")
            for err in errors: buffer.write(err + "\n")
        
        self.output_files[filename] = buffer.getvalue()

    def analyze_generic(self, filename, api_target, op_targets):
        filtered = []
        for d in self.extracted_data:
            match_api = d['api'].lstrip('0') == api_target
            match_op = True
            if op_targets is not None:
                 match_op = d['opcode'].lstrip('0') in op_targets
            
            if match_api and match_op:
                filtered.append(d)
                
        buffer = io.StringIO()
        for d in filtered: buffer.write(f"{d['data']}; {d['api']}; {d['opcode']}; {d['payload']}\n")
        self.output_files[filename] = buffer.getvalue()

    def analyze_api13(self):
        self.analyze_generic("output5.txt", "13", ["1", "2"])

    def analyze_api221(self):
        self.analyze_generic("output6.txt", "221", ["1", "2", "3", "4", "5", "6"])

    def analyze_api9(self):
        self.analyze_generic("output7.txt", "9", ["1", "3"])
    
    def analyze_api11_op3(self):
        self.analyze_generic("output8.txt", "11", ["3"])

    # --- GRAFICI ---
    def get_charts(self):
        total_rows = self.output1_lines_count
        if total_rows == 0: return None

        # Calcolo occorrenze
        c_9_1 = len([d for d in self.extracted_data if d['api'].lstrip('0') == "9" and d['opcode'].lstrip('0') == "1"])
        c_9_3 = len([d for d in self.extracted_data if d['api'].lstrip('0') == "9" and d['opcode'].lstrip('0') == "3"])
        
        c_221_1 = 0
        for d in self.extracted_data:
            if d['api'].lstrip('0') == "221" and d['opcode'].lstrip('0') == "1":
                try:
                    if int(d['payload'].replace('.', '').replace(' ', ''), 16) != 0: c_221_1 += 1
                except: pass

        c_11_7 = len([d for d in self.extracted_data if d['api'].lstrip('0') == "11" and d['opcode'].lstrip('0') == "7"])
        c_11_3_s1 = len([d for d in self.extracted_data if d['api'].lstrip('0') == "11" and d['opcode'].lstrip('0') == "3" and d['source'].lstrip('0') == "1"])
        c_10 = len([d for d in self.extracted_data if d['api'].lstrip('0') == "10"])

        labels = ['API 9 Op 1', 'API 9 Op 3', 'API 221 Op 1\n(Pay!=0)', 'API 11 Op 7', 'API 11 Op 3\n(Src 1)', 'API 10\n(Total)']
        counts = [c_9_1, c_9_3, c_221_1, c_11_7, c_11_3_s1, c_10]
        percents = [(c/total_rows)*100 for c in counts]
        colors = ['red', 'yellow', 'orange', 'blue', 'purple', 'green']

        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.bar(labels, percents, color=colors, edgecolor='black')
        ax.set_ylabel('Percentage (%)')
        ax.set_title(f'Analysis Statistics (Total Lines: {total_rows})')
        ax.set_ylim(0, max(percents + [10]) + 15)

        for bar, count, pct in zip(bars, counts, percents):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height, f'{pct:.2f}%\n(N={count})', ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        return fig

# --- INTERFACCIA STREAMLIT ---

def main():
    st.markdown("""
    <div style='background-color: #f0f2f6; padding: 10px; border-radius: 10px; border: 2px solid #4CAF50; text-align: center;'>
        <h2 style='color: black; margin:0;'>Select File (File Type: .mac/.csv or wmsp.txt)</h2>
    </div>
    """, unsafe_allow_html=True)

    # 1. Machine Selection
    st.subheader("1. Settings")
    col1, col2 = st.columns([1, 2])
    with col1:
        machine = st.radio("Machine Selection", 
                 ["HA-WashMachine", "Dryer-Machine", "Dish-Machine", "VA-WasherMachine", "Cooking"])
        
        if machine != "HA-WashMachine":
            st.warning("Not yet supported. Reverting to default logic.")

    # 2. File Upload
    with col2:
        uploaded_file = st.file_uploader("Upload Log File", type=['mac', 'csv', 'txt'])

    # 3. Custom Inputs
    st.subheader("2. Custom Analysis Parameters")
    c1, c2, c3 = st.columns([1, 1, 2])
    api_in = c1.text_input("Target API (Hex)", value="")
    op_in = c2.text_input("Target Opcode (Hex)", value="")

    # Pulsante Start
    start_btn = c3.button("Start Custom Analysis", type="primary", use_container_width=True)

    # --- ESECUZIONE ---
    if start_btn and uploaded_file:
        analyzer = OmniLogAnalyzerWeb()
        
        with st.spinner('Processing data... Please wait...'):
            # Simulazione pulsazione (attesa breve)
            time.sleep(1)
            
            success = analyzer.run_analysis(uploaded_file, api_in, op_in, None)
            
            if success:
                st.success("Analysis Completed Successfully!")
                
                # Mostra Grafico
                fig = analyzer.get_charts()
                if fig:
                    st.pyplot(fig)

                # Creazione ZIP per Download
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                    for fname, content in analyzer.output_files.items():
                        zip_file.writestr(fname, content)
                
                st.download_button(
                    label="📥 Download All Reports (.zip)",
                    data=zip_buffer.getvalue(),
                    file_name="Analysis_Reports.zip",
                    mime="application/zip"
                )

                st.balloons()
                st.markdown("<h3 style='color: green; text-align: center;'>Best of luck!!!</h3>", unsafe_allow_html=True)
                
            else:
                st.error("Analysis failed.")

    # Descrizione output
    with st.expander("Output Files Description"):
        st.text("""
        output1 = General Log
        output2 = Api and Opcode of Custom Analysis
        output3 = API20 Scr0 (Counter Check)
        output4 = API20 Scr1 (Counter Check)
        output5 = API013
        output6 = API221
        output7 = API009
        output8 = API011 (Op 3)
        """)

if __name__ == "__main__":
    main()