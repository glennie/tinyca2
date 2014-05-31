# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: WORDS.pm,v 1.2 2006/06/28 21:50:42 sm Exp $
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.

use strict;
package GUI::WORDS;

sub new {
   my $that = shift;

   my $self = {
    'none'                  => _("Not set"),
    'user'                  => _("Ask User"),
    'critical'              => _("critical"),
    'noncritical'           => _("not critical"),
    'emailcopy'             => _("Copy Email"),
    'raw'                   => _("raw"),
    'dns'                   => _("DNS Name"),
    'ip'                    => _("IP Address"),
    'mail'                  => _("Email"),
    'server'                => _("SSL Server"),
    'server, client'        => _("SSL Server, SSL Client"),
    'key'                   => _("Key Encipherment"),
    'sig'                   => _("Digital Signature"),
    'keysig'                => _("Key Encipherment, Digital Signature"),
    'objsign'               => _("Object Signing"),
    'client, objsign'       => _("SSL Client, Object Signing"),
    'client, email'         => _("SSL Client, Email(S/MIME)"),
    'client'                => _("SSL Client"),
    'email'                 => _("Email(S/MIME)"),
    'client, email, objsign'=> _("SSL Client, Email, Object Signing"),
    'objCA'                 => _("Object Signing CA"),
    'emailCA'               => _("S/MIME CA"),
    'sslCA'                 => _("SSL CA"),
    'sslCA, emailCA'        => _("SSL CA, S/MIME CA"),
    'sslCA, objCA'          => _("SSL CA, Object Signing CA"),
    'emailCA, objCA'        => _("S/MIME CA, Object Signing CA"),
    'sslCA, emailCA, objCA' => _("SSL CA, S/MIME CA, Object Signing CA"),
    'keyCertSign'           => _("Certificate Signing"),
    'cRLSign'               => _("CRL Signing"),
    'keyCertSign, cRLSign'  => _("Certificate Signing, CRL Signing"),
    'CN'                    => _("Common Name"),
    'EMAIL'                 => _("eMail Address"),
    'O'                     => _("Organization"),
    'OU'                    => _("Organizational Unit"),
    'L'                     => _("Location"),
    'ST'                    => _("State"),
    'C'                     => _("Country"),
    'NOTBEFORE'             => _("Creation Date"),
    'NOTAFTER'              => _("Expiration Date"),
    'KEYSIZE'               => _("Keylength"),
    'PK_ALGORITHM'          => _("Public Key Algorithm"),
    'SIG_ALGORITHM'         => _("Signature Algorithm"),
    'TYPE'                  => _("Type"),
    'SERIAL'                => _("Serial"),
    'STATUS'                => _("Status"),
    'FINGERPRINTMD5'        => _("Fingerprint (MD5)"),
    'FINGERPRINTSHA1'       => _("Fingerprint (SHA1)"),
    _("Not set")                             => 'none',
    _("Ask User")                            => 'user',
    _("critical")                            => 'critical',
    _("not critical")                        => 'noncritical',
    _("Copy Email")                          => 'emailcopy',
    _("raw")                          => 'raw',
    _("DNS Name")                            => 'dns',
    _("Email")                               => 'email',
    _("IP Address")                          => 'ip',
    _("SSL Server")                          => 'server',
    _("SSL Server, SSL Client")              => 'server, client',
    _("Key Encipherment")                    => 'key',
    _("Digital Signature")                   => 'sig',
    _("Key Encipherment, Digital Signature") => 'keysig',
    _("Object Signing")                      => 'objsign',
    _("Email(S/MIME)")                       => 'email',
    _("SSL Client, Email(S/MIME)")           => 'client, email',
    _("SSL Client")                          => 'client',
    _("SSL Client, Object Signing")          => 'client, objsign',
    _("SSL Client, Email, Object Signing")   => 'client, email, objsign',
    _("Object Signing CA")                   => 'objCA',
    _("S/MIME CA")                           => 'emailCA',
    _("SSL CA")                              => 'sslCA',
    _("SSL CA, S/MIME CA")                   => 'sslCA, emailCA',
    _("SSL CA, Object Signing CA")           => 'sslCA, objCA',
    _("S/MIME CA, Object Signing CA")        => 'emailCA, objCA',
    _("SSL CA, S/MIME CA, Object Signing CA")=> 'sslCA, emailCA, objCA',
    _("Certificate Signing")                 => 'keyCertSign',
    _("CRL Signing")                         => 'cRLSign',
    _("Certificate Signing, CRL Signing")    => 'keyCertSign, cRLSign'
   };

   my $class = ref($that) || $that;

   bless($self, $class);

   $self;
}

1
