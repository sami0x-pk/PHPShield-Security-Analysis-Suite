"""PHPShield v3: local-only educational static PHP/security log analyzer."""
from __future__ import annotations
import csv
import json
import re
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

AUTHOR = 'Abdul Samad'
UNIVERSITY = 'Aror University of Art, Architecture, Design & Heritage, Sukkur'
BG, PANEL, RED, WHITE, MUTED = '#080808', '#171717', '#FF3030', '#FFFFFF', '#AAAAAA'
MAX_PHP_SIZE, MAX_LOG_SIZE, MAX_FILES = 2_000_000, 10_000_000, 3000
FIELDS = ['severity', 'rule', 'file', 'line', 'vulnerability', 'recommendation']
PHP_RULES = [
 ('PHP001','CRITICAL','Dynamic code execution',r'\beval\s*\(','Avoid eval() with untrusted input.'),
 ('PHP002','HIGH','OS command execution',r'\b(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(','Avoid OS execution or enforce strict input allowlists.'),
 ('PHP003','HIGH','Potential unsafe deserialization',r'\bunserialize\s*\(','Avoid unserialize() on untrusted input; prefer JSON.'),
 ('PHP004','HIGH','Potential SQL string concatenation',r'(?:query|prepare)\s*\(\s*[\'\"][^\'\"]*[\'\"]\s*\.\s*\$','Use parameterized SQL queries.'),
 ('PHP005','MEDIUM','Potential weak password hashing',r'\b(?:md5|sha1)\s*\(','Use password_hash() and password_verify() for passwords.'),
]
CONFIG_RULES = {
 'display_errors': ('off','MEDIUM','Set display_errors=Off for production.'),
 'expose_php': ('off','LOW','Set expose_php=Off.'),
 'allow_url_include': ('off','HIGH','Disable remote URL includes.'),
 'session.cookie_httponly': ('on','MEDIUM','Enable session.cookie_httponly.'),
 'session.cookie_secure': ('on','MEDIUM','Enable secure session cookies for HTTPS apps.'),
}
LOG_RULES = [
 ('LOG001','HIGH','Possible SQL injection probe',r'(?:union(?:\s|\+|%20)+select|information_schema|(?:%27|\')\s*(?:or|%6fr)\s+1\s*=\s*1)','Review request context, parameterized queries and WAF logs.'),
 ('LOG002','MEDIUM','Possible path traversal probe',r'(?:\.\./|\.\.\\|%2e%2e(?:%2f|/)|%252e%252e)','Inspect requested path and server-side path normalization.'),
 ('LOG003','MEDIUM','Possible cross-site scripting probe',r'(?:<script\b|%3cscript|javascript:)','Verify output escaping and context-aware input handling.'),
 ('LOG004','HIGH','Possible command-injection probe',r'(?:;|%3b)\s*(?:whoami|id|uname)\b','Review input validation; do not pass user input to shell.'),
]

def entry(severity, rule, file, line, vulnerability, recommendation):
    return dict(zip(FIELDS, [severity, rule, str(file), line, vulnerability, recommendation]))

def scan_php_file(path):
    p=Path(path)
    if p.stat().st_size > MAX_PHP_SIZE: raise ValueError('PHP file exceeds 2 MB safety limit')
    results=[]
    for n, line in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
        if len(line)>20000: continue
        for rid, level, title, pattern, fix in PHP_RULES:
            if re.search(pattern, line, re.I):
                results.append(entry(level,rid,p,n,title,fix))
    return results

def scan_php_folder(folder):
    folder=Path(folder)
    if not folder.is_dir(): raise ValueError('Choose an existing PHP project folder.')
    results=[]; count=0; skipped=0
    for path in folder.rglob('*'):
        if path.suffix.lower()!='.php': continue
        if count+skipped >= MAX_FILES: break
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_PHP_SIZE:
                skipped+=1; continue
            results.extend(scan_php_file(path)); count+=1
        except (OSError, ValueError): skipped+=1
    return results,count,skipped

def normalize(value):
    val=value.strip().strip('"\'').lower()
    return {'1':'on','yes':'on','true':'on','0':'off','no':'off','false':'off'}.get(val,val)

def scan_php_config(path):
    p=Path(path)
    if p.stat().st_size>MAX_PHP_SIZE: raise ValueError('Config exceeds 2 MB safety limit')
    findings=[]
    for n, line in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(),1):
        line=line.strip()
        if not line or line.startswith((';','#','[')) or '=' not in line: continue
        key,value=line.split('=',1); key=key.strip().lower()
        if key not in CONFIG_RULES: continue
        expected, severity, fix=CONFIG_RULES[key]
        actual=normalize(value.split(';',1)[0])
        if actual != expected:
            findings.append(entry(severity,'CONFIG',p,n,f'{key} = {actual} (recommended: {expected})',fix))
    return findings

def scan_web_log(path):
    p=Path(path)
    if p.stat().st_size>MAX_LOG_SIZE: raise ValueError('Log exceeds 10 MB safety limit')
    findings=[]
    for n,line in enumerate(p.read_text(encoding='utf-8',errors='replace').splitlines(),1):
        if len(line)>20000: continue
        for rid,level,title,pattern,fix in LOG_RULES:
            if re.search(pattern,line,re.I): findings.append(entry(level,rid,p,n,title,fix))
    return findings


# ---------- v4 persistent history and reporting ----------
import os
import sqlite3
import textwrap
from collections import Counter

APP_VERSION = '4.0.0'
SEVERITY_WEIGHTS = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
ACCENT = '#ff404a'
DATA_DIR = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'PHPShield'


def risk_indicator(findings):
    """Bounded heuristic indicator, not probability or a CVSS rating."""
    score = sum(SEVERITY_WEIGHTS.get(f.get('severity'), 0) for f in findings)
    return min(100, score)


def summary_counts(findings):
    counts = Counter(f.get('severity') for f in findings)
    return {level: counts.get(level, 0) for level in SEVERITY_WEIGHTS}


def initialize_db(db_path=None):
    path = Path(db_path) if db_path else DATA_DIR / 'history.sqlite3'
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            files_scanned INTEGER NOT NULL,
            findings_json TEXT NOT NULL)''')
    return path


def record_scan(db_path, kind, source, files_scanned, findings):
    payload = json.dumps(findings, ensure_ascii=False)
    with sqlite3.connect(db_path) as db:
        cur = db.execute(
            'INSERT INTO scans (created_at,kind,source,files_scanned,findings_json) VALUES (?,?,?,?,?)',
            (datetime.now().isoformat(timespec='seconds'), kind, str(source), files_scanned, payload))
        return cur.lastrowid


def list_scans(db_path):
    with sqlite3.connect(db_path) as db:
        return db.execute('SELECT id,created_at,kind,source,files_scanned,findings_json FROM scans ORDER BY id DESC LIMIT 500').fetchall()


def delete_scan(db_path, scan_id):
    with sqlite3.connect(db_path) as db:
        db.execute('DELETE FROM scans WHERE id=?', (int(scan_id),))


def build_report(findings, files_scanned, source, kind='Combined'):
    return {
        'application': 'PHPShield', 'version': APP_VERSION,
        'developer': AUTHOR, 'university': UNIVERSITY,
        'generated_at': datetime.now().isoformat(timespec='seconds'),
        'type': kind, 'source': str(source), 'files_scanned': int(files_scanned),
        'total_findings': len(findings), 'severity_counts': summary_counts(findings),
        'risk_indicator': risk_indicator(findings),
        'disclaimer': 'Heuristic findings require manual verification. Risk indicator is NOT likelihood of compromise.',
        'findings': list(findings),
    }


def export_pdf(report, filename):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    from xml.sax.saxutils import escape
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='PSHead', parent=styles['Heading1'], fontSize=19, leading=24, textColor=colors.HexColor('#b00020'), spaceAfter=12))
    styles.add(ParagraphStyle(name='PSBody', parent=styles['BodyText'], fontSize=9, leading=13, spaceAfter=6))
    styles.add(ParagraphStyle(name='PSSmall', parent=styles['BodyText'], fontSize=8, leading=11, spaceAfter=5))
    doc = SimpleDocTemplate(str(filename), pagesize=A4, leftMargin=43, rightMargin=43, topMargin=43, bottomMargin=43)
    content = [Paragraph('PHPShield | Security Assessment', styles['PSHead']),
               Paragraph(escape(f"Generated: {report['generated_at']}"), styles['PSBody']),
               Paragraph(escape(f"Developer: {AUTHOR} | {UNIVERSITY}"), styles['PSBody']),
               Paragraph(escape(f"Source: {report['source']}"), styles['PSBody']), Spacer(1, 8)]
    tabledata=[['Files scanned', 'Findings', 'Risk indicator / 100'],
               [str(report['files_scanned']), str(report['total_findings']), str(report['risk_indicator'])]]
    table=Table(tabledata, colWidths=[160,160,160]); table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#3c1119')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),.4,colors.HexColor('#aaaaaa')),
        ('BOTTOMPADDING',(0,0),(-1,-1),10),('TOPPADDING',(0,0),(-1,-1),10)]))
    content += [table, Spacer(1,12), Paragraph('Severity breakdown',styles['Heading2'])]
    content.append(Paragraph(escape(' | '.join(f'{k}: {v}' for k,v in report['severity_counts'].items())),styles['PSBody']))
    content.append(Paragraph(escape(report['disclaimer']),styles['PSBody']))
    content.append(Paragraph('Detailed findings and remediation',styles['Heading2']))
    if not report['findings']:
        content.append(Paragraph('No findings recorded by the enabled heuristic checks.',styles['PSBody']))
    for i,f in enumerate(report['findings'],1):
        title=escape(f"{i}. {f['severity']} | {f['rule']} | {f['vulnerability']}")
        location=escape(f"{f['file']} : line {f['line']}")
        rec=escape(str(f['recommendation']))
        content.append(KeepTogether([Paragraph(title,styles['Heading3']),
            Paragraph(location,styles['PSSmall']),Paragraph('Recommendation: '+rec,styles['PSBody'])]))
    doc.build(content)


class PHPShield:
    def __init__(self, root, db_path=None):
        self.root=root
        root.title('PHPShield v4 | Final Security Analysis Suite')
        root.geometry('1390x860'); root.minsize(1040,650); root.configure(bg=BG)
        self.findings=[]; self.files_scanned=0; self.events=[]; self.visible=[]; self.source='No source selected'
        self.folder=''; self.kind='Combined'; self.search_var=tk.StringVar(); self.severity_var=tk.StringVar(value='ALL')
        self.db_path=initialize_db(db_path)
        self.configure_style()
        self.build_gui()
        self.refresh_history()
        self.update_metrics()
        self.log('System ready — local analysis only')

    def configure_style(self):
        st=ttk.Style(self.root); st.theme_use('clam')
        st.configure('Treeview',background='#111111',fieldbackground='#111111',foreground=WHITE,rowheight=29,font=('Consolas',10),borderwidth=0)
        st.configure('Treeview.Heading',background='#3b1015',foreground='#ff9ba0',font=('Consolas',10,'bold'))
        st.map('Treeview',background=[('selected','#7d1220')],foreground=[('selected',WHITE)])
        st.configure('TNotebook',background=BG,borderwidth=0)
        st.configure('TNotebook.Tab',background=PANEL,foreground=WHITE,padding=(15,10))
        st.map('TNotebook.Tab',background=[('selected','#8b1822')])
        st.configure('TCombobox',fieldbackground='#222222',foreground='#111111')

    def label(self, parent, txt, size=11, color=WHITE, bold=False):
        return tk.Label(parent,text=txt,bg=parent.cget('bg'),fg=color,font=('Segoe UI',size,'bold' if bold else 'normal'))

    def button(self,parent,txt,fn):
        return tk.Button(parent,text=txt,command=fn,bg='#A41928',fg=WHITE,activebackground=RED,activeforeground=WHITE,
                         relief='flat',padx=10,pady=9,cursor='hand2',font=('Segoe UI',9,'bold'))

    def build_gui(self):
        h=tk.Frame(self.root,bg=BG); h.pack(fill='x',padx=22,pady=(16,8))
        self.label(h,'⬡  PHPShield',27,ACCENT,True).pack(side='left')
        self.label(h,'v4.0  /  SECURITY INTELLIGENCE  /  LOCAL DEFENSIVE ANALYSIS',10,MUTED,True).pack(side='right')
        tools=tk.Frame(self.root,bg=PANEL,padx=10,pady=10); tools.pack(fill='x',padx=20)
        for text,func in [('📂 FOLDER',self.choose_folder),('SCAN PHP',self.scan_project),('PHP CONFIG',self.check_config),
                          ('ANALYZE LOG',self.analyze_log),('PDF REPORT',self.save_pdf),('CSV',self.save_csv),
                          ('JSON',self.save_json),('CLEAR',self.clear)]:
            self.button(tools,text,func).pack(side='left',padx=4)
        self.source_label=self.label(self.root,'SOURCE: None',9,MUTED);self.source_label.pack(anchor='w',padx=24,pady=5)
        self.tabs=ttk.Notebook(self.root);self.tabs.pack(fill='both',expand=True,padx=20,pady=(2,8))
        self.dashboard=tk.Frame(self.tabs,bg=BG); self.findings_tab=tk.Frame(self.tabs,bg=BG)
        self.analytics_tab=tk.Frame(self.tabs,bg=BG); self.history_tab=tk.Frame(self.tabs,bg=BG)
        self.activity_tab=tk.Frame(self.tabs,bg=BG);self.about_tab=tk.Frame(self.tabs,bg=BG)
        for name,frame in [('DASHBOARD',self.dashboard),('FINDINGS',self.findings_tab),('ANALYTICS',self.analytics_tab),('SCAN HISTORY',self.history_tab),('ACTIVITY',self.activity_tab),('ABOUT',self.about_tab)]:
            self.tabs.add(frame,text='  '+name+'  ')
        metrics=tk.Frame(self.dashboard,bg=BG);metrics.pack(fill='x',padx=10,pady=18)
        self.cards={}
        for key in ['Files Scanned','Findings','Critical','High','Medium','Low','Risk / 100']:
            frame=tk.Frame(metrics,bg=PANEL,padx=9,pady=16);frame.pack(side='left',expand=True,fill='both',padx=4)
            self.label(frame,key.upper(),9,MUTED).pack()
            widget=self.label(frame,'0',23,ACCENT,True);widget.pack(pady=5);self.cards[key]=widget
        box=tk.Frame(self.dashboard,bg=PANEL,padx=20,pady=24);box.pack(fill='both',expand=True,padx=14,pady=(0,15))
        self.label(box,'SECURITY OVERVIEW',16,ACCENT,True).pack(anchor='w',pady=(0,12))
        self.overview=tk.Text(box,wrap='word',bg=PANEL,fg=WHITE,relief='flat',font=('Consolas',12),height=15)
        self.overview.pack(fill='both',expand=True)
        self.overview.insert('1.0','Run a PHP source, configuration, or log scan to see security indicators.')
        control=tk.Frame(self.findings_tab,bg=BG);control.pack(fill='x',padx=10,pady=12)
        self.label(control,'SEARCH',10,ACCENT,True).pack(side='left',padx=(0,8))
        search=tk.Entry(control,textvariable=self.search_var,bg='#242424',fg=WHITE,insertbackground=WHITE,relief='flat',font=('Consolas',11))
        search.pack(side='left',fill='x',expand=True,padx=(0,12),ipady=6)
        self.search_var.trace_add('write',lambda *_:self.render_findings())
        self.label(control,'SEVERITY',10,ACCENT,True).pack(side='left',padx=(0,8))
        combo=ttk.Combobox(control,textvariable=self.severity_var,values=['ALL','CRITICAL','HIGH','MEDIUM','LOW'],width=12,state='readonly')
        combo.pack(side='left'); combo.bind('<<ComboboxSelected>>',lambda _:self.render_findings())
        outer=tk.Frame(self.findings_tab,bg=BG);outer.pack(fill='both',expand=True,padx=10)
        cols=['severity','rule','file','line','vulnerability','recommendation']
        self.finding_tree=ttk.Treeview(outer,columns=cols,show='headings')
        for c,width in [('severity',100),('rule',90),('file',250),('line',70),('vulnerability',270),('recommendation',390)]:
            self.finding_tree.heading(c,text=c.upper());self.finding_tree.column(c,width=width,stretch=(c in ('file','vulnerability','recommendation')))
        self.finding_tree.tag_configure('CRITICAL',foreground='#ff5964')
        self.finding_tree.tag_configure('HIGH',foreground='#ffad72')
        self.finding_tree.tag_configure('MEDIUM',foreground='#f3f3f3')
        self.finding_tree.tag_configure('LOW',foreground='#aab2bc')
        y=ttk.Scrollbar(outer,orient='vertical',command=self.finding_tree.yview)
        x=ttk.Scrollbar(outer,orient='horizontal',command=self.finding_tree.xview)
        self.finding_tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        y.pack(side='right',fill='y');x.pack(side='bottom',fill='x');self.finding_tree.pack(fill='both',expand=True)
        self.finding_tree.bind('<<TreeviewSelect>>',self.detail_selected)
        self.detail=tk.Text(self.findings_tab,height=5,bg=PANEL,fg=WHITE,wrap='word',relief='flat',font=('Consolas',10),padx=10,pady=8)
        self.detail.pack(fill='x',padx=10,pady=10)
        a=tk.Frame(self.analytics_tab,bg=BG);a.pack(fill='both',expand=True,padx=16,pady=12)
        self.label(a,'SEVERITY DISTRIBUTION',14,ACCENT,True).pack(anchor='w')
        self.chart_holder=tk.Frame(a,bg=BG);self.chart_holder.pack(fill='both',expand=True)
        self.chart_canvas=None
        self.button(a,'REFRESH ANALYTICS',self.update_chart).pack(anchor='e',pady=6)
        hist_controls=tk.Frame(self.history_tab,bg=BG);hist_controls.pack(fill='x',padx=10,pady=10)
        self.button(hist_controls,'REFRESH',self.refresh_history).pack(side='left',padx=4)
        self.button(hist_controls,'LOAD SELECTED',self.load_history).pack(side='left',padx=4)
        self.button(hist_controls,'DELETE SELECTED',self.remove_history).pack(side='left',padx=4)
        self.label(hist_controls,'Saved locally in SQLite (up to 500 recent sessions shown)',9,MUTED).pack(side='right')
        self.hist_tree=ttk.Treeview(self.history_tab,columns=('id','date','kind','source','files','findings'),show='headings')
        for c,w in [('id',60),('date',165),('kind',100),('source',500),('files',80),('findings',85)]:
            self.hist_tree.heading(c,text=c.upper());self.hist_tree.column(c,width=w)
        self.hist_tree.pack(fill='both',expand=True,padx=10,pady=(0,12))
        self.activity=tk.Text(self.activity_tab,bg=PANEL,fg=WHITE,relief='flat',font=('Consolas',11),wrap='word',padx=15,pady=15)
        self.activity.pack(fill='both',expand=True,padx=12,pady=12)
        info=(f'PHPShield v{APP_VERSION}  |  Educational defensive PHP security analyzer\n\n'
              f'Developer: {AUTHOR}\nUniversity: {UNIVERSITY}\n\n'
              'Modules: PHP static checks, php.ini review, access log indicators, PDF / CSV / JSON exports, '
              'SQLite session history, analytics and finding filters.\n\n'
              'IMPORTANT: This tool does not execute PHP files, attack web servers, or connect to websites. '
              'Patterns can generate false positives or miss vulnerabilities. '\
              'A clean result does not prove the system secure. The risk indicator is a heuristic, not CVSS or probability.\n\n'
              'Check only files, projects and logs you own or are authorized to review.')
        tk.Label(self.about_tab,text=info,justify='left',wraplength=980,bg=BG,fg=WHITE,font=('Segoe UI',12),padx=24,pady=24).pack(anchor='nw')
        self.status=self.label(self.root,'● READY',9,ACCENT);self.status.pack(anchor='w',padx=25,pady=(0,5))
        self.label(self.root,f'DEVELOPED BY {AUTHOR.upper()}   |   {UNIVERSITY.upper()}',8,MUTED).pack(pady=(0,10))
        self.tabs.bind('<<NotebookTabChanged>>',self.on_tab)

    def on_tab(self,_=None):
        if self.tabs.select()==str(self.analytics_tab): self.update_chart()

    def log(self,event):
        self.events.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'),event))
        self.activity.insert('end',f'[{self.events[-1][0]}] {event}\n')
        self.activity.see('end')

    def update_metrics(self):
        values={'Files Scanned':self.files_scanned,'Findings':len(self.findings),'Risk / 100':risk_indicator(self.findings)}
        values.update({k.title():v for k,v in summary_counts(self.findings).items()})
        for name,widget in self.cards.items():widget.config(text=str(values.get(name,0)))
        breakdown=summary_counts(self.findings)
        text=(f'Source: {self.source}\nFiles scanned: {self.files_scanned}\n'
              f'Total potential findings: {len(self.findings)}\n\n'
              + '\n'.join(f'  {k:9} : {v}' for k,v in breakdown.items())
              + f'\n\nHeuristic risk indicator: {risk_indicator(self.findings)}/100 (NOT probability)\n'
              '----------------------------------------\n'
              'Findings are indicators requiring manual investigation.\n'
              'No live probing or exploitation is performed.')
        self.overview.delete('1.0','end');self.overview.insert('end',text)

    def render_findings(self):
        self.finding_tree.delete(*self.finding_tree.get_children())
        search=self.search_var.get().casefold().strip(); sev=self.severity_var.get()
        self.visible=[]
        for finding in self.findings:
            if sev!='ALL' and finding['severity']!=sev:continue
            if search and not any(search in str(v).casefold() for v in finding.values()):continue
            self.visible.append(finding)
            self.finding_tree.insert('', 'end', iid=str(len(self.visible)-1),tags=(finding['severity'],),
                                     values=tuple(finding[c] for c in ['severity','rule','file','line','vulnerability','recommendation']))

    def detail_selected(self,_=None):
        ids=self.finding_tree.selection()
        if not ids:return
        try:f=self.visible[int(ids[0])]
        except (IndexError,ValueError):return
        self.detail.delete('1.0','end');self.detail.insert('end',f"{f['severity']} | {f['rule']} | {f['file']}:{f['line']}\n{f['vulnerability']}\nREMEDIATION: {f['recommendation']}")

    def choose_folder(self):
        folder=filedialog.askdirectory(title='Select local PHP project folder')
        if folder:self.folder=folder;self.source=folder;self.source_label.config(text=f'SOURCE: {folder}');self.log(f'Selected project: {folder}')

    def accept_scan(self,kind,source,new,files):
        # A scan replaces current findings; persistent history retains earlier sessions.
        self.kind=kind;self.source=str(source);self.findings=list(new);self.files_scanned=files
        self.source_label.config(text=f'SOURCE: {source}')
        self.search_var.set('');self.severity_var.set('ALL')
        self.update_metrics();self.render_findings()
        try:
            scan_id=record_scan(self.db_path,kind,source,files,new)
            self.refresh_history();self.log(f'{kind} scan saved as #{scan_id}: {len(new)} findings')
        except (sqlite3.Error,OSError) as exc:
            self.log('Could not save history: '+str(exc));messagebox.showwarning('History warning',str(exc))
        self.status.config(text=f'● {kind.upper()} COMPLETE | {len(new)} POTENTIAL FINDINGS')
        self.tabs.select(self.findings_tab)
        messagebox.showinfo('PHPShield scan complete',f'{kind}: {len(new)} potential findings\nFiles scanned: {files}')

    def scan_project(self):
        if not self.folder:messagebox.showwarning('Folder required','Choose a PHP project folder first.');return
        try:
            results,count,skipped=scan_php_folder(self.folder)
            self.accept_scan('PHP',self.folder,results,count)
            if skipped:self.log(f'{skipped} PHP files skipped (size, permissions or file limits)')
        except (OSError,ValueError) as exc:messagebox.showerror('Scan error',str(exc))

    def check_config(self):
        path=filedialog.askopenfilename(title='Select php.ini',filetypes=[('INI files','*.ini'),('All files','*.*')])
        if not path:return
        try:self.accept_scan('CONFIG',path,scan_php_config(path),0)
        except (OSError,ValueError) as exc:messagebox.showerror('Config error',str(exc))

    def analyze_log(self):
        path=filedialog.askopenfilename(title='Select web-server access log',filetypes=[('Log files','*.log'),('Text files','*.txt'),('All files','*.*')])
        if not path:return
        try:self.accept_scan('LOG',path,scan_web_log(path),0)
        except (OSError,ValueError) as exc:messagebox.showerror('Log error',str(exc))

    def refresh_history(self):
        if not hasattr(self,'hist_tree'):return
        self.hist_tree.delete(*self.hist_tree.get_children())
        try:
            for scan_id,created,kind,source,files,payload in list_scans(self.db_path):
                self.hist_tree.insert('','end',iid=str(scan_id),values=(scan_id,created,kind,source,files,len(json.loads(payload))))
        except (sqlite3.Error,ValueError) as exc:self.log('History read error: '+str(exc))

    def load_history(self):
        selected=self.hist_tree.selection()
        if not selected:messagebox.showinfo('History','Select a scan first.');return
        target=int(selected[0])
        try:
            row=next((r for r in list_scans(self.db_path) if r[0]==target),None)
            if row is None:raise ValueError('Selected scan is no longer available.')
            self.findings=json.loads(row[5]);self.files_scanned=row[4];self.kind=row[2];self.source=row[3]
            self.source_label.config(text=f'SOURCE: {self.source}')
            self.search_var.set('');self.severity_var.set('ALL')
            self.update_metrics();self.render_findings()
            self.log(f'Loaded saved scan #{target}')
            self.status.config(text=f'● RESTORED SESSION #{target}')
            self.tabs.select(self.findings_tab)
        except (sqlite3.Error,ValueError,TypeError) as exc:messagebox.showerror('Load error',str(exc))

    def remove_history(self):
        selected=self.hist_tree.selection()
        if not selected:return
        if not messagebox.askyesno('Delete saved session','Delete the selected scan from local history?'):return
        try:delete_scan(self.db_path,int(selected[0]));self.refresh_history();self.log('Deleted history entry '+selected[0])
        except (sqlite3.Error,ValueError) as exc:messagebox.showerror('History error',str(exc))

    def get_report(self):return build_report(self.findings,self.files_scanned,self.source,self.kind)

    def save_pdf(self):
        path=filedialog.asksaveasfilename(title='Save PHPShield PDF',initialfile='PHPShield_Report.pdf',defaultextension='.pdf',filetypes=[('PDF report','*.pdf')])
        if not path:return
        try:export_pdf(self.get_report(),path);self.log('Exported PDF: '+path);messagebox.showinfo('Report saved','PDF assessment report saved successfully.')
        except Exception as exc:messagebox.showerror('PDF export error',str(exc))

    def save_csv(self):
        path=filedialog.asksaveasfilename(initialfile='PHPShield_Report.csv',defaultextension='.csv',filetypes=[('CSV','*.csv')])
        if not path:return
        try:
            with open(path,'w',encoding='utf-8',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=FIELDS);writer.writeheader();writer.writerows(self.findings)
            self.log('Exported CSV: '+path);messagebox.showinfo('Report saved','CSV saved successfully.')
        except (OSError,ValueError) as exc:messagebox.showerror('CSV export error',str(exc))

    def save_json(self):
        path=filedialog.asksaveasfilename(initialfile='PHPShield_Report.json',defaultextension='.json',filetypes=[('JSON','*.json')])
        if not path:return
        try:
            Path(path).write_text(json.dumps(self.get_report(),indent=2,ensure_ascii=False),encoding='utf-8')
            self.log('Exported JSON: '+path);messagebox.showinfo('Report saved','JSON saved successfully.')
        except (OSError,ValueError) as exc:messagebox.showerror('JSON export error',str(exc))

    def update_chart(self):
        try:
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            if self.chart_canvas:
                self.chart_canvas.get_tk_widget().destroy();self.chart_canvas=None
            c=summary_counts(self.findings)
            fig=Figure(figsize=(9,4.3),dpi=100,facecolor=BG)
            ax=fig.add_subplot(111,facecolor=PANEL)
            levels=list(c);values=list(c.values())
            bars=ax.bar(levels,values,color=['#fc354d','#ff8c42','#e7e7e7','#8c9ba9'])
            for bar,count in zip(bars,values):ax.text(bar.get_x()+bar.get_width()/2,count+.04,str(count),ha='center',color=WHITE)
            ax.set_ylim(0,max(1,max(values)+1));ax.tick_params(colors=WHITE)
            for s in ax.spines.values():s.set_color('#555555')
            ax.set_ylabel('Number of heuristic findings',color=WHITE)
            fig.tight_layout()
            self.chart_canvas=FigureCanvasTkAgg(fig,master=self.chart_holder)
            self.chart_canvas.draw();self.chart_canvas.get_tk_widget().pack(fill='both',expand=True)
        except Exception as exc:self.log('Analytics unavailable: '+str(exc))

    def clear(self):
        self.findings=[];self.files_scanned=0;self.source='No source selected';self.kind='Combined'
        self.search_var.set('');self.severity_var.set('ALL');self.update_metrics();self.render_findings()
        self.detail.delete('1.0','end');self.status.config(text='● CURRENT SESSION CLEARED');self.log('Cleared current session (history preserved)')


def main():
    root=tk.Tk()
    PHPShield(root)
    root.mainloop()

if __name__=='__main__':main()
