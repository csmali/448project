//
//  CertificateAuthorityPanel.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  GUI class for the Certificate Authority Initialization.
//
package Chat;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class CertificateAuthorityLoginPanel extends JPanel {

    JPasswordField _privateKeyPassField;
  //  JPasswordField _permissionsFilePassField;
    JTextField _portField;
    JTextField _keystoreFileNameField;
  //  JTextField _permissionsFileNameField;
    JLabel _errorLabel;
    JButton _startupButton;
    CertificateAuthority _ca;

    public CertificateAuthorityLoginPanel(CertificateAuthority ca) {
        _ca = ca;

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("CertificateAuthorityPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    void componentInit() throws Exception {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        JLabel label;

        setLayout(gridBag);

        addLabel(gridBag, "Certificate Server Startup Panel", SwingConstants.CENTER,
                1, 0, 2, 1);
        addLabel(gridBag, "KeyStore File Name: ", SwingConstants.LEFT, 1, 1, 1, 1);
        addLabel(gridBag, "KeyStore (Private Key) Password: ", SwingConstants.LEFT, 1, 2, 1, 1);
  //      addLabel(gridBag, "Permission File Name: ", SwingConstants.LEFT, 1, 3, 1, 1);
  //      addLabel(gridBag, "Permission File Password: ", SwingConstants.LEFT, 1, 4, 1, 1);
        addLabel(gridBag, "Port Number: ", SwingConstants.LEFT, 1, 5, 1, 1);


        _keystoreFileNameField = new JTextField();
        addField(gridBag, _keystoreFileNameField, 2, 1, 1, 1);

        _privateKeyPassField = new JPasswordField();
        _privateKeyPassField.setEchoChar('*');
        addField(gridBag, _privateKeyPassField, 2, 2, 1, 1);

  //      _permissionsFileNameField = new JTextField();
  //      addField(gridBag, _permissionsFileNameField, 2, 3, 1, 1);

  //      _permissionsFilePassField = new JPasswordField();
  //      _permissionsFilePassField.setEchoChar('*');
  //      addField(gridBag, _permissionsFilePassField, 2, 4, 1, 1);

        _portField = new JTextField();
        addField(gridBag, _portField, 2, 5, 1, 1);

        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER,
                1, 6, 2, 1);

        // just for testing purposs
        _errorLabel.setForeground(Color.red);

        _startupButton = new JButton("Startup");
        c.gridx = 1;
        c.gridy = 8;
        c.gridwidth = 2;
        gridBag.setConstraints(_startupButton, c);
        add(_startupButton);

        _startupButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                startup();
            }
        });
    }

    JLabel addLabel(GridBagLayout gridBag, String labelStr, int align,
            int x, int y, int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        JLabel label = new JLabel(labelStr);
        if (align == SwingConstants.LEFT) {
            c.anchor = GridBagConstraints.WEST;
        } else {
            c.insets = new Insets(10, 0, 10, 0);
        }
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(label, c);
        add(label);

        return label;
    }

    void addField(GridBagLayout gridBag, JTextField field, int x, int y,
            int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        field.setPreferredSize(new Dimension(96,
                field.getMinimumSize().height));
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(field, c);
        add(field);
    }

    private void startup() {
        //System.out.println("Called startup");

        int _caPort;

        String _keystoreFileName = _keystoreFileNameField.getText();
//        String _permissionsFileName = _permissionsFileNameField.getText();
        char[] _privateKeyPass = _privateKeyPassField.getPassword();
     //   char[] _permissionsFilePass = _permissionsFilePassField.getPassword();

        if (_privateKeyPass.length == 0
                /*|| _permissionsFilePass.length == 0*/
                || _portField.getText().equals("")
                || _keystoreFileName.equals("")
                /*|| _permissionsFileName.equals("")*/) {

            _errorLabel.setText("Missing required field.");

            return;

        } else {

            _errorLabel.setText(" ");

        }

        try {

            _caPort = Integer.parseInt(_portField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return;
        }

        //System.out.println("Certificate Authority is starting up ...");

        switch (_ca.startup(_keystoreFileName,
                _privateKeyPass,
               /* _permissionsFileName,
                _permissionsFilePass,*/
                _caPort)) {

            case CertificateAuthority.SUCCESS:
                //  Nothing happens, this panel is now hidden
                _errorLabel.setText(" ");
                break;
            case CertificateAuthority.KEYSTORE_FILE_NOT_FOUND:
                _errorLabel.setText("KeyStore file not found!");
                break;
    /*        case CertificateAuthority.PERMISSIONS_FILE_NOT_FOUND:
                _errorLabel.setText("Permissions file not found!");
                break;
            case CertificateAuthority.PERMISSIONS_FILE_TAMPERED:
                _errorLabel.setText("Somebody messed up ther perms file!");
                break;
    */        case CertificateAuthority.ERROR:
                _errorLabel.setText("Unknown Error!");
                break;
        }

        //System.out.println("Certificate Authority startup complete");
    }
}
