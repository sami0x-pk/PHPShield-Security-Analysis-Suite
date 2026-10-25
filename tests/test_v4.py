import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from app import (scan_php_folder, scan_php_config, scan_web_log,
                 build_report, export_pdf, initialize_db, record_scan,
                 list_scans, delete_scan, risk_indicator, summary_counts)

class TestPHPShieldV4(unittest.TestCase):
    def test_risk_and_report(self):
        items=[{'severity': 'CRITICAL','rule':'PHP001','file':'sample.php','line':4,'vulnerability':'Dynamic code execution','recommendation':'Avoid eval.'},
               {'severity': 'MEDIUM','rule':'PHP005','file':'sample.php','line':2,'vulnerability':'Weak hashing','recommendation':'Use password_hash.'}]
        report=build_report(items,1,'a/b')
        self.assertEqual(risk_indicator(items),14)
        self.assertEqual(report['risk_indicator'],14)
        self.assertEqual(summary_counts(items)['CRITICAL'],1)
        self.assertEqual(report['total_findings'],2)
        self.assertEqual(risk_indicator(items*12),100)

    def test_history_persists_and_removes(self):
        with tempfile.TemporaryDirectory() as d:
            db=initialize_db(Path(d)/'history.db')
            values=[{'severity':'LOW','rule':'CONFIG','file':'php.ini','line':3,'vulnerability':'expose_php','recommendation':'Off'}]
            rid=record_scan(db,'CONFIG','php.ini',0,values)
            saved=list_scans(db)
            self.assertEqual(len(saved),1)
            self.assertEqual(json.loads(saved[0][5]),values)
            delete_scan(db,rid)
            self.assertFalse(list_scans(db))

    def test_pdf_output(self):
        with tempfile.TemporaryDirectory() as d:
            items=[{'severity':'HIGH','rule':'LOG001','file':'log & <>.txt','line':2,'vulnerability':'Probe <pattern>','recommendation':'Review & validate.'}]
            path=Path(d)/'report.pdf'
            export_pdf(build_report(items,0,'test'),path)
            self.assertGreater(path.stat().st_size,1000)
            self.assertEqual(path.read_bytes()[:4],b'%PDF')

    def test_sample_scanners(self):
        samples=Path(__file__).resolve().parents[1]/'sample_data'
        php,count,skipped=scan_php_folder(samples)
        self.assertEqual((count,len(php)),(1,3))
        self.assertEqual(len(scan_php_config(samples/'php_test.ini')),5)
        self.assertEqual(len(scan_web_log(samples/'access.log')),3)

if __name__=='__main__':unittest.main()
