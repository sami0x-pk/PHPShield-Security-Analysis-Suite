import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import scan_php_folder, scan_php_config, scan_web_log
class Tests(unittest.TestCase):
 def test_source(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'sample.php').write_text('<?php\n$x=md5($password);\n$z=unserialize($data);\neval($input);\n')
   findings,count,skipped=scan_php_folder(d)
   self.assertEqual((count,skipped,len(findings)),(1,0,3))
 def test_ini(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'php.ini';p.write_text('display_errors=On\nexpose_php=On\nallow_url_include=On\nsession.cookie_httponly=Off\nsession.cookie_secure=Off\n')
   self.assertEqual(len(scan_php_config(p)),5)
 def test_log(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'access.log';p.write_text('GET /index.php?id=1+union+select+password HTTP/1.1\nGET /etc/../passwd HTTP/1.1\nGET /?q=%3Cscript%3E HTTP/1.1\n')
   self.assertEqual(len(scan_web_log(p)),3)
if __name__=='__main__':unittest.main()
