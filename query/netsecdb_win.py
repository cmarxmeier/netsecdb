#!C:\Users\alladin\netsecdb\venv\Scripts\python
# network security query script in python qt running on win11 64bit
# (c) 2025 by alladin@routeme.de
#
import sys
from PyQt6 import QtWidgets, QtGui, QtSql, QtCore
from ipaddress import ip_address

class MyWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        # setting title 
        self.setWindowTitle("NetsecDB Query ") 

        self.setGeometry(10, 500, 1900, 800)

        # Display a JPEG logo
        label = QtWidgets.QLabel(self)
        pixmap = QtGui.QPixmap('netsecdb.png')
        label.setPixmap(pixmap)
        label.resize(pixmap.width(), pixmap.height())


        # time_label
        self.time_label = QtWidgets.QLabel(self)  # New QLabel for displaying elapsed time


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
        # switch database host
        self.db.setHostName('localhost')  # localhost
        #self.db.setHostName('192.168.80.171')  # other db-host
        # database credentials
        self.db.setDatabaseName('whois')  # replace with your database name
        self.db.setPort(5432)             # Default PostgreSQL port
        self.db.setUserName('user')  # replace with your username
        self.db.setPassword('password')  # replace with your password

        if not self.db.open():
                QMessageBox.warning(self, 'Database Error',
                                  'Failed to open database connection.')
                return


        # Layout setup
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(label)
        layout.addWidget(self.ip_input)
        layout.addWidget(submit_button)
        layout.addWidget(exit_button)
        layout.addWidget(self.time_label)
        self.setLayout(layout)



    def search_database(self):
        ip_str = self.ip_input.text().strip() 
        try:
            ip_address(ip_str)  # validate IP address
        except ValueError:
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid IP address")
            return

        timer = QtCore.QElapsedTimer()  # New QElapsedTimer object
        timer.start()
        
        # first SQL Query
        query1 = QtSql.QSqlQuery("SELECT id,netrange,netCIDRVAL as CIDR,nethandle,netname,org_id,orgname,abusemail,left(country, 8)as country  FROM netblock WHERE netCIDRVAL >> '"+ ip_str +"' ORDER BY netCIDRVAL DESC")

        if not query1.isActive():
            QtWidgets.QMessageBox.warning(self, "Error", "Database error")
            return

        # get id of first record
        if query1.first():  # move cursor to first row
            id_str = query1.value(0)  # get value from first column (id)


        # second SQL Query
        query2 = QtSql.QSqlQuery("SELECT id,netCIDRVAL as CIDR,iscustomer as customer,isspamming as spam,ishacking as hack,isportscanning as pscan,iswebspammer as webspam,isblocked as blocked,ismailblocked as smtp,ispopblocked as imap,iswebblocked as web,isftpblocked as ftp ,isdnsblocked as dns,issshblocked as ssh,ispleskblocked as webadmin,isallblocked as all FROM netblock WHERE id='"+ str(id_str) + "'")
        if not query2.isActive():
              QtWidgets.QMessageBox.warning(self, "Error", "Database error")
              return

	  # get netcidr of first record
        if query2.first():  # move cursor to first row
            netcidr_str = query2.value(1)  # get value from first column (netcidr)
	    
        elapsed_time = timer.elapsed() / 1000  # Calculate the elapsed time in seconds
        self.time_label.setText("Searching for "+ ip_str + " with record id: "+ str(id_str) +" cidr: "+ str(netcidr_str) +" took {:.3f} s ".format(elapsed_time))  # Display the elapsed time on the QLabel widget


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
        if not layout.itemAt(5):  # if no table is already displayed, add one
             layout.addWidget(view1)
        else:
             layout.replaceWidget(layout.itemAt(5).widget(), view1)  # otherwise, replace the existing one with the new one
        # second window
        view2 = QtWidgets.QTableView()
        view2.setModel(self.model2)
        # scale table to content
        view2.resizeColumnsToContents()
        if not layout.itemAt(6):  # if no table is already displayed, add one
             layout.addWidget(view2)
        else:
             layout.replaceWidget(layout.itemAt(6).widget(), view2)  # otherwise, replace the existing one with the new one


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
