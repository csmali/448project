//
//  AuthServerActivityPanel.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  GUI class for displaying information about the Auth. Server
//
//  You should not need to modify this class.
package Chat;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class AuthServerActivityPanel extends JPanel {

    JTextArea _outputArea;
    JButton _quitButton;
    AuthServer _as;

    public AuthServerActivityPanel(AuthServer as) {
        _as = as;

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("AuthServerActivity error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    void componentInit() throws Exception {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();

        setLayout(gridBag);

        addLabel(gridBag, "AS Activity: ", SwingConstants.LEFT, 0, 0, 1, 1);
        _outputArea = addArea(gridBag, new Dimension(400, 192), 0, 1);
        _outputArea.setEditable(false);

        _quitButton = new JButton("Exit");
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

    void quit() {
        _as.quit();
    }
}
