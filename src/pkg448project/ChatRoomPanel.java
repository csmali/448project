//  ChatRoomPanel.java
//
//  Last modified 1/30/2000 by Alan Frindell
//
//  GUI class for the chat room.
//
//  You should not need to modify this class.
package Chat;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class ChatRoomPanel extends JPanel {

    JTextArea _inputArea;
    JTextArea _outputArea;
    JButton _quitButton;
    ChatClient _client;

    public ChatRoomPanel(ChatClient client) {
        _client = client;

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("ChatRoomPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    void componentInit() throws Exception {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();

        setLayout(gridBag);

        addLabel(gridBag, "Chat Room: ", SwingConstants.LEFT, 0, 0, 1, 1);
        _outputArea = addArea(gridBag, new Dimension(400, 192), 0, 1);
        _outputArea.setEditable(false);

        addLabel(gridBag, "Your Message: ", SwingConstants.LEFT, 0, 2, 1, 1);
        _inputArea = addArea(gridBag, new Dimension(400, 96), 0, 3);
        _inputArea.addKeyListener(new KeyAdapter() {

            public void keyTyped(KeyEvent e) {
                inputKeyTyped(e);
            }
        });

        _quitButton = new JButton("Leave Chat Room");
        _quitButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                quit();
            }
        });
        c.insets = new Insets(4, 4, 4, 4);
        c.weighty = 1.0;   //request any extra vertical space
        c.gridx = 2;
        c.gridy = 4;
        c.gridwidth = GridBagConstraints.REMAINDER;
        c.anchor = GridBagConstraints.SOUTHEAST; //bottom of space
        gridBag.setConstraints(_quitButton, c);
        add(_quitButton);

    }

    JLabel addLabel(GridBagLayout gridBag, String labelStr, int align,
            int x, int y, int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        JLabel label = new JLabel(labelStr);
        if (align == SwingConstants.LEFT) {
            c.insets = new Insets(10, 4, 0, 4);
        }
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(label, c);
        add(label);

        return label;
    }

    JTextArea addArea(GridBagLayout gridBag, Dimension prefSize,
            int x, int y) {
        JScrollPane scroller;
        JTextArea area = new JTextArea();
        GridBagConstraints c = new GridBagConstraints();

        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(4, 4, 4, 4);
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = 3;
        scroller = new JScrollPane(area);
        scroller.setPreferredSize(prefSize);
        gridBag.setConstraints(scroller, c);
        add(scroller);

        return area;
    }

    public JTextArea getOutputArea() {
        return _outputArea;
    }

    void inputKeyTyped(KeyEvent e) {
        String msg;

        if (e.getKeyChar() == KeyEvent.VK_ENTER) {
            msg = _inputArea.getText();
            _inputArea.setText("");
            if (msg.length() == 0) {
                return;
            }
            _client.sendMessage(msg);
        }
    }

    void quit() {
        _client.quit();
    }
}
