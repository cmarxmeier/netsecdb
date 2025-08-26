#!C:\Users\alladin\netsecdb\venv\Scripts\python
import sys
import re
import ipaddress
from PyQt6 import QtWidgets, QtGui, QtSql, QtCore, uic
from ipaddress import ip_address

# pdf export
from PIL import ImageGrab, Image
from reportlab.lib.pagesizes import A4, landscape, letter
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
import os

lastip = ''
lHeight, lWidth = landscape(A4)

class MyWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        # setting title 
        self.setWindowTitle("NetsecDB CIDR-Report ") 

        self.setGeometry(10, 500, 1900, 800)

        # Display a JPEG logo
        label = QtWidgets.QLabel(self)
        pixmap = QtGui.QPixmap('netsecdb.png')
        label.setPixmap(pixmap)
        label.resize(pixmap.width(), pixmap.height())


        # time_label
        self.time_label = QtWidgets.QLabel(self)  # New QLabel for displaying elapsed time

        # meta tables
        self.meta_label =  QtWidgets.QLabel(self)  # New QLabel for displaying metadata 

        # Input field for IP address
        self.ip_input = QtWidgets.QLineEdit()
        self.ip_input.setStyleSheet("QLineEdit { background-color: yellow }")


        # Submit button
        submit_button = QtWidgets.QPushButton('Search in DB')
        submit_button.clicked.connect(self.search_database)
        submit_button.setStyleSheet(
           "QPushButton::hover{"
           "background-color: #3fff59;"
           "border: none;"
           "},"       
           "Qpushbutton {"
           "background-color: darkgreen;"
           "border: none;"
           "}" 
	)  # Set background color to green

        # Export PDF Button
        pdf_button = QtWidgets.QPushButton('export PDF')
        pdf_button.clicked.connect(self.exportpdf)
        pdf_button.setStyleSheet(
           "QPushButton::hover{"
           "background-color: #5EABFF;"
           "border: none;"
           "},"       
           "Qpushbutton {"
           "background-color: blue;"
           "border: none;"
           "}" 
	)  # Set background color to blue



        # Exit button
        exit_button = QtWidgets.QPushButton('Exit')
        exit_button.clicked.connect(QtWidgets.QApplication.instance().quit)
        exit_button.setStyleSheet(
           "QPushButton::hover{"
           "background-color: #ffd2cf;"
           "border: none;"
           "},"
           "Qpushbutton {"
           "background-color: darkred;"
           "border: none;"
           "}" 
        )  # Set background color to red



        # Database connection setup
        self.db = QtSql.QSqlDatabase.addDatabase('QPSQL')
        self.db.setHostName('localhost')  # replace with your host name
        #self.db.setHostName('192.168.80.124')  # replace with your host name
        self.db.setDatabaseName('whois')  # replace with your database name
        self.db.setPort(5432)             # Default PostgreSQL port
        self.db.setUserName('user')  # replace with your username
        self.db.setPassword('password')  # replace with your password

        if not self.db.open():
                QtWidgets.QMessageBox.critical(self, "DB-Error", "No database connect.")
                sys.exit()
                return

        

        # Layout setup
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(label)
        layout.addWidget(self.ip_input)
        layout.addWidget(submit_button)
        layout.addWidget(pdf_button)
        layout.addWidget(exit_button)
        layout.addWidget(self.time_label)
        layout.addWidget(self.meta_label)
        self.setLayout(layout)

    
        
    def exportpdf(self):
      # add export routine for pdf screendump
      print("pdf export triggered")
      # Get the geometry of the application window to define the area for screenshot
      geometry = self.geometry()
      #x = geometry.x() + 10  # Adjust to avoid window border issues (if any)
      #y = geometry.y() + 20  # Adjust to avoid title bar and borders (if any)
      x = geometry.x()
      y = geometry.y()

      width = geometry.width()
      height = geometry.height()

      # Capture the screen area that corresponds to the application window
      screenshot = ImageGrab.grab(bbox=(x, y, x+width, y+height))

      # Save screenshot as a temporary PNG file
      temp_image_path = os.path.join(os.getcwd(), 'screenshot.png')
      screenshot.save(temp_image_path)

      # Define the scaling factor based on desired PDF page dimensions or dynamically calculate
      # Let's assume we want to scale it to fit A4 landscape size, which is 8.27 inches x 11.69 inches (approximately)
      pdf_width = 827   # in points
      pdf_height = 1169  # in points

      # Calculate scaling factors
      scale_x = pdf_width / width
      scale_y = pdf_height / height
      scale = min(scale_x, scale_y)  # Use the smallest factor to fit within PDF page dimensions

      # Define new scaled dimensions
      scaled_width = int(width * scale)
      scaled_height = int(height * scale)

      # Create a PDF and insert the screenshot into it
      lastipfilename= lastip.replace(":","_")
      lastipfilename2 = lastipfilename.replace(".","_")
      pngfilename = 'reports/netsecdb_cidrreport_' + lastipfilename2 + '.pdf'
      output_pdf_path = os.path.join(os.getcwd(), pngfilename)
      c = Canvas(pngfilename, pagesize=landscape(A4))

      # Draw the scaled screenshot on the PDF
      c.drawImage(temp_image_path, 0, 0, scaled_width, scaled_height)
      # Draw Text Title
      # set font
      c.setFont("Helvetica", 48)
      c.drawString(150, 500, "NetsecDB CIDR-Report")
      c.save()

      # Optional: Remove the temporary PNG file
      os.remove(temp_image_path)

      print(f"Screenshot saved to {output_pdf_path}")
      QtWidgets.QMessageBox.critical(self, "PDF export", "successfully exported to pdf.")

    def search_database(self):
        ip_str = self.ip_input.text().strip()
        global lastcidr
        global lastip
        lastip = ip_str        
        try:
            ip_address(ip_str)  # validate IP address
        except ValueError:
            QtWidgets.QMessageBox.critical(self, "Error", "Invalid IP address")
            return
	# check, if IP is Version 4 or 6:        
        ip_version = ipaddress.ip_address(ip_str).version

        timer = QtCore.QElapsedTimer()  # New QElapsedTimer object
        timer.start()
        
        # first SQL Query
        query1 = QtSql.QSqlQuery("SELECT id,netrange,netCIDRVAL as CIDR,nethandle,netname,org_id,orgname,abusemail,left(country, 8)as country  FROM netblock WHERE netCIDRVAL >> '"+ ip_str +"' ORDER BY netCIDRVAL DESC")

        if not query1.isActive():
            QtWidgets.QMessageBox.critical(self, "Error", "Error accessing whois database")
            return

        # get id of first record
        if query1.first():  # move cursor to first row
            id_str = query1.value(0)  # get value from first column (id)


        # second SQL Query
        query2 = QtSql.QSqlQuery("SELECT id,netCIDRVAL as CIDR,iscustomer as customer,isspamming as spam,ishacking as hack,isportscanning as pscan,iswebspammer as webspam,isblocked as blocked,ismailblocked as smtp,ispopblocked as imap,iswebblocked as web,isftpblocked as ftp ,isdnsblocked as dns,issshblocked as ssh,ispleskblocked as webadmin,isallblocked as all FROM netblock WHERE id='"+ str(id_str) + "'")
        if not query2.isActive():
              QtWidgets.QMessageBox.critical(self, "Error", "Error accessing whois database")
              return
 
        # get netcidr of first record
        if query2.first():  # move cursor to first row
            netcidr_str = query2.value(1)  # get value from first column (netcidr)

        meta_str = ""

        if ip_version == 4: # case IP is V4
            # print("IP is V4")
            # get IP-records from tables within cidr netrange
	    # bothosts 
            string4 = "bothosts: "
            valuecount = 0
            meta_str = meta_str + string4  
            query3 =  QtSql.QSqlQuery("SELECT bothosts.netip FROM bothosts WHERE trim(bothosts.netip)::inet << '"+ netcidr_str + "'::cidr AND bothosts.isblocked = true ORDER BY bothosts.network ASC") 
            if not query3.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on bothosts")
                   return
            # loop table-values and concat to output-string 
            while (query3.next()):
                   valuecount = valuecount + 1
                   if valuecount == 20:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query3.value(0);
                   meta_str = meta_str + string4 + ", "
            
            # dnsbots 
            string4 = "\ndnsbots: "
            valuecount = 0
            meta_str = meta_str + string4 
            query4 = QtSql.QSqlQuery("SELECT dnsbots.netip FROM dnsbots WHERE trim(dnsbots.netip)::inet << '"+ netcidr_str + "'::cidr AND dnsbots.isblocked = true ORDER BY dnsbots.network ASC")
            if not query4.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on dnsbots")
                   return
            # loop table-values and concat to output-string
            while (query4.next()):
                   valuecount = valuecount + 1
                   if valuecount == 20:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query4.value(0);
                   meta_str = meta_str + string4 + ", "

            # mailerbots 
            string4 = "\nmailerbots: "
            valuecount = 0
            meta_str = meta_str + string4
            query5 = QtSql.QSqlQuery("SELECT mailerbots.netip FROM mailerbots WHERE trim(mailerbots.netip)::inet << '"+ netcidr_str + "'::cidr AND mailerbots.isblocked = true ORDER BY mailerbots.network ASC")
            if not query5.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on mailerbots")
                   return
            # loop table-values and concat to output-string
            while (query5.next()):
                   valuecount = valuecount + 1
                   if valuecount == 20:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query5.value(0);
                   meta_str = meta_str + string4 + ", "


            # openproxies 
            string4 = "\nopenproxies: "
            valuecount = 0
            meta_str = meta_str + string4
            query6 = QtSql.QSqlQuery("SELECT openproxies.netip FROM openproxies WHERE trim(openproxies.netip)::inet << '"+ netcidr_str + "'::cidr AND openproxies.isblocked = true ORDER BY openproxies.network ASC")
            if not query6.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on openproxies")
                   return
            # loop table-values and concat to output-string
            while (query6.next()):
                   valuecount = valuecount + 1
                   if valuecount == 20:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query6.value(0);
                   meta_str = meta_str + string4 + ", "

            
            # torexitnodes
            string4 = "\ntorexitnodes: "
            valuecount = 0
            meta_str = meta_str + string4
            query8 = QtSql.QSqlQuery("SELECT torexitnodes.netip FROM torexitnodes WHERE trim(torexitnodes.netip)::inet << '"+ netcidr_str + "'::cidr AND torexitnodes.isblocked = true ORDER BY torexitnodes.network ASC")
            if not query8.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on torexitnodes")
                   return
            # loop table-values and concat to output-string
            while (query8.next()):
                   valuecount = valuecount + 1
                   if valuecount == 20:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query8.value(0);
                   meta_str = meta_str + string4 + ", "

            # torexitnodes_history 
            string4 = "\ntorexit_hist: "
            valuecount = 0
            meta_str = meta_str + string4
            query9 = QtSql.QSqlQuery("SELECT torexitnodeshistory.netip FROM torexitnodeshistory WHERE trim(torexitnodeshistory.netip)::inet << '"+ netcidr_str + "'::cidr AND torexitnodeshistory.isblocked = true ORDER BY torexitnodeshistory.network ASC")
            if not query9.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on torexitnodeshistory")
                   return
            # loop table-values and concat to output-string
            while (query9.next()):
                   valuecount = valuecount + 1
                   if valuecount == 20:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query9.value(0);
                   meta_str = meta_str + string4 + ", "



        if ip_version == 6: # case IP is V6
             # print("IP is V6")
            # get IP-records from tables within cidr netrange
             # bothosts_v6
             string6 = "bothosts: "
             valuecount = 0
             meta_str=meta_str + string6
             query3 =  QtSql.QSqlQuery("SELECT bothosts_ipv6.netip FROM bothosts_ipv6 WHERE trim(bothosts_ipv6.netip)::inet << '"+ netcidr_str + "'::cidr AND bothosts_ipv6.isblocked = true ORDER BY bothosts_ipv6.netip ASC")
             if not query3.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on bothosts")
                   return
             # loop table-values and concat to output-string
             while (query3.next()):
                   valuecount = valuecount + 1
                   if valuecount == 8:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query3.value(0);
                   meta_str = meta_str + string4 + ","

             # dnsbots_v6
             string4 = "\ndnsbots: "
             valuecount = 0
             meta_str = meta_str + string4
             query4 = QtSql.QSqlQuery("SELECT dnsbots_ipv6.netip FROM dnsbots_ipv6 WHERE trim(dnsbots_ipv6.netip)::inet << '"+ netcidr_str + "'::cidr AND dnsbots_ipv6.isblocked = true ORDER BY dnsbots_ipv6.netip ASC")
             if not query4.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on dnsbots")
                   return
             # loop table-values and concat to output-string
             while (query4.next()):
                   valuecount = valuecount + 1
                   if valuecount == 8:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query4.value(0);
                   meta_str = meta_str + string4 + ","

             # mailerbots_v6
             string4 = "\nmailerbots: "
             valuecount = 0
             meta_str = meta_str + string4
             query5 = QtSql.QSqlQuery("SELECT mailerbots_ipv6.netip FROM mailerbots_ipv6 WHERE trim(mailerbots_ipv6.netip)::inet << '"+ netcidr_str + "'::cidr AND mailerbots_ipv6.isblocked = true ORDER BY mailerbots_ipv6.netip ASC")
             if not query5.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on mailerbots")
                   return
             # loop table-values and concat to output-string
             while (query5.next()):
                   valuecount = valuecount + 1
                   if valuecount == 8:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query5.value(0);
                   meta_str = meta_str + string4 + ", "


             # openproxies_v6
             string4 = "\nopenproxies: "
             valuecount = 0
             meta_str = meta_str + string4
             query6 = QtSql.QSqlQuery("SELECT openproxiesv6.netip FROM openproxiesv6 WHERE trim(openproxiesv6.netip)::inet << '"+ netcidr_str + "'::cidr AND openproxiesv6.isblocked = true ORDER BY openproxiesv6.netip ASC")
             if not query6.isActive():
                   QtWidgets.QMessageBox.critical(self, "Error", "Database error on openproxies")
                   return
             # loop table-values and concat to output-string
             while (query6.next()):
                   valuecount = valuecount + 1
                   if valuecount == 8:
                       meta_str = meta_str + "\n"
                       valuecount = 0
                   string4 = query6.value(0);
                   meta_str = meta_str + string4 + ", "
             

        elapsed_time = timer.elapsed() / 1000  # Calculate the elapsed time in seconds
        self.time_label.setText("Searching for IPv"+str(ip_version)+" "+ ip_str  + " with record id: "+ str(id_str) +" cidr: "+ str(netcidr_str)+" took {:.3f} s ".format(elapsed_time))  # Display the elapsed time on the QLabel widget

        lastcidr=str(netcidr_str)

        #self.time_label.setFont(QtGui.QFont("Times",weight=QtGui.QFont.Bold))
        self.meta_label.setText(meta_str)

        self.model1 = QtSql.QSqlQueryModel()
        self.model1.setQuery(query1)

        self.model2 = QtSql.QSqlQueryModel()
        self.model2.setQuery(query2)        

        # clear input field
        self.ip_input.setText("") 
       
	    # show result tables
        # first window
        view1 = QtWidgets.QTableView()
        view1.setModel(self.model1)
        layout = self.layout()
        # scale table to content
        view1.resizeColumnsToContents()
        if not layout.itemAt(7):  # if no table is already displayed, add one
             layout.addWidget(view1)
        else:
             layout.replaceWidget(layout.itemAt(6).widget(), view1)  # otherwise, replace the existing one with the new one
        # second window
        view2 = QtWidgets.QTableView()
        view2.setModel(self.model2)
        # scale table to content
        view2.resizeColumnsToContents()
        if not layout.itemAt(8):  # if no table is already displayed, add one
             layout.addWidget(view2)
        else:
             layout.replaceWidget(layout.itemAt(7).widget(), view2)  # otherwise, replace the existing one with the new one

       # print pdf from window
       

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
