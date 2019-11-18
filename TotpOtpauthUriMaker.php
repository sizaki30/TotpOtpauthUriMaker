<?php
/**
 * This PHP class make an otpauth URI by entering the TOTP (RFC6238) secret, issuer, and account name.
 *
 * @author sizaki30
 * @license MIT
 */
class TotpOtpauthUriMaker
{
    // Base 32 Encoding (No padding '=' required)
    // https://tools.ietf.org/html/rfc3548#section-5
    // https://tools.ietf.org/html/rfc3548#section-2.2 is not required
    private function _encodeBase32($secret)
    {
        if (empty($secret)) {
            return null;
        }
       
        // Convert secret to binary.
        $binary_secret = '';
        foreach(str_split($secret) as $chara) {
            $binary_secret .= sprintf('%08b', ord($chara));
        }

        // Divide into arrays by 5 bits.
        $binary_secret_array = str_split($binary_secret, 5);

        // Encode to base32.
        $base32alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $base32_secret  = '';
        foreach($binary_secret_array as $bin) {
            $bin_pad = str_pad($bin, 5, 0); // 0 padding if less than 5 bits
            $base32_secret .= $base32alphabet[base_convert($bin_pad, 2, 10)];
        }
           
        return $base32_secret;
    }

    private function _main($params)
    {
        $issuer = urlencode(str_replace(':', '', $params['issuer']));
       
        $accountname = urlencode(str_replace(':', '', $params['accountname']));
       
        $label = $issuer . urlencode(':') . $accountname;
       
        if ($params['base32_encode'] === true) {
            $secret = $this->_encodeBase32($params['secret']);
        } else {
            $secret = $params['secret'];
        }
       
        $supported_algorithms = array('SHA1', 'SHA256', 'SHA512');
        $algorithm = (in_array($params['algorithms'], $supported_algorithms)) ? $params['algorithms'] : 'SHA1';
       
        $supported_digits = array(6, 8);
        $digits = (in_array($params['digits'], $supported_digits)) ? $params['digits'] : 6;
       
        $period = ((int)$params['period']) ? (int)$params['period'] : 30;
       
        $url = "otpauth://totp/{$label}?secret={$secret}"
             . "&issuer={$issuer}&algorithm={$algorithm}&digits={$digits}&period={$period}";
       
        return $url;
    }

    public function make($params)
    {
        return $this->_main($params);
    }
}
