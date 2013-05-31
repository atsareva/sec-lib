<?php

class SecConfig
{

    /**
     * Absolute path to sec_lib directory.
     * Notice: Always ends with slash (/)
     *
     * @var string
     */
    public $_secBaseDir = '';

    /**
     * Name of the session.
     *
     * @var string
     */
    public $_secSessionName = '';

    /**
     * Adds security checks to cookie data. Sets and checks absolute cookie lifetime.
     * 1 - secure cookies (recommended); 0 - not secure
     *
     * @var int
     */
    public $_secSecureCookies = 1;

    /**
     * Adds security checks to session data. Sets and checks absolute session lifetime.
     * Sets and checks idletime of the session lifetime. Shortens cookie lifetime, sets httpOnly-Flag.
     * 1 - secure session (recommended); 0 - not secure
     *
     * @var int
     */
    public $_secSecureSession = 1;

    /**
     * If set, the user will be redirected there in case of an security error, invalid tokens, detected attacks.
     * Not Empty - redirect to (recommended); Empty - do not redirect
     *
     * @var string
     */
    public $_secOnerrorRedirectTo = 'http://labs-blog.com/';

    /**
     * The session is only valid, when the same webbrowser is used. A weak but
     * recommended protection against sessions stealing.
     * 1 - check (recommended); 0 - do not check
     *
     * @var int
     */
    public $_secSessionHeadersCheck = 1;

    /**
     * Shows PHP error messages which have been supressed by the library. It also
     * shows errors which has been set with the function "secError()".
     * 1 - show; 0 - hide (recommended)
     *
     * @var int
     */
    public $_secErrors = 0;

    /**
     * Error messages, detected attacks and token failure can be written to an logfile.
     * 1 - write log (recommended); 0 - do not
     *
     * @var int
     */
    public $_secLog = 1;

    /**
     * Sets the session lifetime. Overwrites PHPs own settings. Session lifetime gets
     * renewed with every usage of the application.
     * 
     * @var int
     */
    public $_secSessionLifeTime = 7200; /* two hours */

    /**
     * Sets the absolute session lifetime. Absolute lifetime cannot be renewed. After
     * this time, the current session will be deleted.
     * 
     * @var int
     */
    public $_secSessionAbsoluteLifeTime = 21600; /* six hours */

    /**
     * Sets the absolute lifetime of CSRF-tokens. Absolute lifetime cannot be renewed. After
     * this time, the token will be invalid.
     * 
     * @var int
     */
    public $_secTokenLifeTime = 7200;

    /**
     * Sets the interval to renew the session id. All data will be transcripted.
     * 0 - refresh on each call
     * 
     * @var int
     */
    public $_secSessionRefresh = 7200;

    /**
     * What happens when:
     * session expires, user agents changes, token is not valid, globals are overwritten
     * "delay"  - Delays response for 50 seconds.
     * "logout" - Deletes current session.
     * "logout" - user will be redirected to $_secOnerrorRedirectTo
     * 
     * delay, logout, redirect (options separated by space)
     * 
     * @var string
     */
    public $_secIdsOnAttackAction = 'logout redirect';

    /**
     * What happens when a value does not match its filter.
     * "delay"  - Delays response for 50 seconds.
     * "logout" - Deletes current session.
     * "logout" - user will be redirected to $_secOnerrorRedirectTo
     *
     * delay, logout, redirect (options separated by space)
     *
     * @var string
     */
    public $_secFilterNoMathAction = 'redirect';
    
    private $_secStartOk = true;

    public function __construct()
    {
        if (!$this->_secBaseDir)
            $this->_secBaseDir = dirname(__FILE__) . DIRECTORY_SEPARATOR;

        if ($this->_secErrors)
        {
            error_reporting(E_USER_ERROR | E_USER_WARNING);
            set_error_handler('secInstallErrorHandler');
        }
        restore_error_handler();
    }

    public function secInstallErrorHandler($code = '', $msg = '', $file = '', $line = '')
    {
        if ($this->_secStartOk)
        {
            switch ($code)
            {
                case E_ERROR:
                case E_WARNING:
                    /* DON'T ADD $msg, $file OR $line TO THIS MESSAGE! RISC OF INFORMATION DISCLOSURE! */
                    echo ('$_secBaseDir - path in sec_lib configuration seems to be wrong!');
                    $this->_secStartOk = false;
                    break;
            }
        }
    }

}
