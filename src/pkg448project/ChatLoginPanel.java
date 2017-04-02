//  ChatLoginPanel.java
//
//  Last modified 1/30/2000 by Alan Frindell
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  GUI class for the login panel.
//
//  You should not have to modify this class.
package Chat;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class ChatLoginPanel extends JPanel {

    JTextField _loginNameField;
    JPasswordField _passwordField;
    JTextField _serverHostField;
    JTextField _serverPortField;
    JTextField _serverRoomField;

    JTextField _caHostField;
    JTextField _caPortField;
    JTextField _keyStoreNameField;
    JPasswordField _keyStorePasswordField;
    JLabel _errorLabel;
    JButton _connectButton;
    ChatClient _client;

    public ChatLoginPanel(ChatClient client) {
        _client = client;

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("ChatLoginPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    void componentInit() throws Exception {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        JLabel label;

        setLayout(gridBag);

        addLabel(gridBag, "Welcome to Chat", SwingConstants.CENTER,
                1, 0, 2, 1);
        addLabel(gridBag, "Username: ", SwingConstants.LEFT, 1, 1, 1, 1);
        addLabel(gridBag, "Password: ", SwingConstants.LEFT, 1, 2, 1, 1);
        addLabel(gridBag, "Server Host Name: ", SwingConstants.LEFT, 1, 3, 1, 1);
        addLabel(gridBag, "Server Port: ", SwingConstants.LEFT, 1, 4, 1, 1);
        addLabel(gridBag, "Room: ", SwingConstants.LEFT, 1, 5, 1, 1);

        _loginNameField = new JTextField();
        addField(gridBag, _loginNameField, 2, 1, 1, 1);
        
        _passwordField = new JPasswordField();
        _passwordField.setEchoChar('*');
        addField(gridBag, _passwordField, 2, 2, 1, 1);
        
        _serverHostField = new JTextField();
        addField(gridBag, _serverHostField, 2, 3, 1, 1);
        _serverPortField = new JTextField();
        addField(gridBag, _serverPortField, 2, 4, 1, 1);


        _serverRoomField = new JTextField();
        addField(gridBag, _serverRoomField, 2, 5, 1, 1);

        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER,
                1, 6, 2, 1);

        // just for testing purpose
        _loginNameField.setText("cs470");
        _passwordField.setText("cs470");
        _serverHostField.setText("localhost");
        _serverPortField.setText("7777");
        _serverRoomField.setText("A");
        _errorLabel.setForeground(Color.red);

        _connectButton = new JButton("Connect");
        c.gridx = 1;
        c.gridy = 10;
        c.gridwidth = 2;
        gridBag.setConstraints(_connectButton, c);
        add(_connectButton);

        _connectButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                connect();
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

    private void connect() {

        int serverPort;

        String loginName = _loginNameField.getText();
        char[] password = _passwordField.getPassword();

        String serverHost = _serverHostField.getText();
        String serverRoom = _serverRoomField.getText();

        if (loginName.equals("")
                || password.length == 0
                || serverHost.equals("")
                || _serverPortField.getText().equals("")
                || _serverRoomField.getText().equals("")) {

            _errorLabel.setText("Missing required field.");

            return;

        } else {

            _errorLabel.setText(" ");

        }

        try {

            serverPort = Integer.parseInt(_serverPortField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return;
        }

        System.out.println("We are connecting to ...");

        switch (_client.connect(loginName,
                password,
                serverHost,
                serverPort,
                serverRoom)) {

            case ChatClient.SUCCESS:
                //  Nothing happens, this panel is now hidden
                _errorLabel.setText(" ");
                break;
            case ChatClient.CONNECTION_REFUSED:
            case ChatClient.BAD_HOST:
                _errorLabel.setText("Connection Refused!");
                break;
            case ChatClient.ERROR:
                _errorLabel.setText("ERROR!  Stop That!");
                break;

        }

        System.out.println("We finished connecting to ...");

    }
}