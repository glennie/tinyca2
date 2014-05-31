# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: TCONFIG.pm,v 1.2 2006/06/28 21:50:42 sm Exp $
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

package TCONFIG;

use POSIX;

sub new {
   my $self  = {};
   my $that  = shift;
   my $class = ref($that) || $that;

   bless($self, $class);
}

sub init_config {
   my ($self, $main, $ca) = @_;

   my($file, @lines, $i, $section, $l, $k, $v);

   if(not defined($ca)) {
     $ca = $main->{'CA'}->{'actca'};
   }
   if(not defined($ca)) {
      GUI::HELPERS::print_warning(_("Please select a CA first"));
      return;
   }

   $file = $main->{'CA'}->{$ca}->{'cnf'};

   open(IN, "<$file") || do {
      GUI::HELPERS::print_warning(_("Can't open configuration"));
      return;
   };

   @lines = <IN>;
   close IN;
   chomp(@lines);

   # clean old configuration
   foreach $k (keys(%$self)) {
      delete($self->{$k});
   }

   foreach $l (@lines) {
      next if $l =~ /^#/;
      next if $l =~ /^$/;
      next if $l =~ /^ *$/;

      # find section
      if($l =~ /\[\s*([^\s]+)\s*\]/) {
         $section = $1;
      } elsif ($l =~ /^([^\s\t]+)[\s\t]*=[\s\t]*([^\s\t]+.*)$/) {
         if($section eq "ca" ||
            $section eq "policy_client" ||
            $section eq "policy_server" ||
            $section eq "policy_ca" ||
            $section eq "req" ||
            $section eq "req_distinguished_name" ||
            $section eq "v3_req" ||
            $section eq "req_attributes") {
            if(not defined($self->{$section})) {
               $self->{$section} = [];
            }
            push(@{$self->{$section}}, $l);
         } else {
            $k = $1;
            $v = $2;
            # really ugly hack XXX
            if($v =~ /ENV::(\w+)$/) {
               $ENV{$1} = 'dummy';
            }
            if(not defined($self->{$section})) {
               $self->{$section} = {};
            }
            $self->{$section}->{$k} = $v;
         }
      }
   }

   # store nsSslServerName information
   if(defined($self->{'server_cert'}->{'nsSslServerName'})) {
      if($self->{'server_cert'}->{'nsSslServerName'}
            =~ /ENV:/) {
         $self->{'server_cert'}->{'nsSslServerName'} = 'user';
      }
   }else {
      $self->{'server_cert'}->{'nsSslServerName'} = 'none';
   }

   # store subjectAltName information
   # ca
   if(defined($self->{'v3_ca'}->{'subjectAltName'})) {
      if($self->{'v3_ca'}->{'subjectAltName'} eq 'email:copy') {
         $self->{'v3_ca'}->{'subjectAltName'} = 'emailcopy';
      }
   }else {
      $self->{'v3_ca'}->{'subjectAltName'} = 'none';
   }

   # server
   if(defined($self->{'server_cert'}->{'subjectAltName'})) {
      if($self->{'server_cert'}->{'subjectAltName'}
            =~ /ENV:.*IP/) {
         $self->{'server_cert'}->{'subjectAltNameType'} = 'ip';
         $self->{'server_cert'}->{'subjectAltName'} = 'user';
      }elsif($self->{'server_cert'}->{'subjectAltName'}
            =~ /ENV:.*DNS/) {
         $self->{'server_cert'}->{'subjectAltNameType'} = 'dns';
         $self->{'server_cert'}->{'subjectAltName'} = 'user';
      }elsif($self->{'server_cert'}->{'subjectAltName'}
            =~ /ENV:.*RAW/) {
         $self->{'server_cert'}->{'subjectAltNameType'} = 'raw';
         $self->{'server_cert'}->{'subjectAltName'} = 'user';
      }elsif($self->{'server_cert'}->{'subjectAltName'}
            eq 'email:copy') {
         $self->{'server_cert'}->{'subjectAltName'} = 'emailcopy';
         $self->{'server_cert'}->{'subjectAltNameType'} = 'ip';
      }
   }else {
      $self->{'server_cert'}->{'subjectAltNameType'} = 'ip';
      $self->{'server_cert'}->{'subjectAltName'} = 'none';
   }

   # client
   if(defined($self->{'client_cert'}->{'subjectAltName'})) {
      if($self->{'client_cert'}->{'subjectAltName'}
            =~ /ENV:.*IP/) {
         $self->{'client_cert'}->{'subjectAltNameType'} = 'ip';
         $self->{'client_cert'}->{'subjectAltName'} = 'user';
      }elsif($self->{'client_cert'}->{'subjectAltName'}
            =~ /ENV:.*DNS/) {
         $self->{'client_cert'}->{'subjectAltNameType'} = 'dns';
         $self->{'client_cert'}->{'subjectAltName'} = 'user';
      }elsif($self->{'client_cert'}->{'subjectAltName'}
            =~ /ENV:.*EMAIL/) {
         $self->{'client_cert'}->{'subjectAltNameType'} = 'mail';
         $self->{'client_cert'}->{'subjectAltName'} = 'user';
      }elsif($self->{'client_cert'}->{'subjectAltName'}
            =~ /ENV:.*RAW/) {
         $self->{'client_cert'}->{'subjectAltNameType'} = 'raw';
         $self->{'client_cert'}->{'subjectAltName'} = 'user';
      }elsif($self->{'client_cert'}->{'subjectAltName'}
            eq 'email:copy') {
         $self->{'client_cert'}->{'subjectAltName'} = 'emailcopy';
         $self->{'client_cert'}->{'subjectAltNameType'} = 'ip';
      }
   }else {
      $self->{'client_cert'}->{'subjectAltNameType'} = 'ip';
      $self->{'client_cert'}->{'subjectAltName'} = 'none';
   }

   foreach my $sect ('server_cert', 'client_cert', 'v3_ca') {
      # store nsRevocationUrl information
      if(defined($self->{$sect}->{'nsRevocationUrl'})) {
         if($self->{$sect}->{'nsRevocationUrl'}
               =~ /ENV:/) {
            $self->{$sect}->{'nsRevocationUrl'} = 'user';
         }
      }else {
         $self->{$sect}->{'nsRevocationUrl'} = 'none';
      }

      # store nsRenewalUrl information
      if(defined($self->{$sect}->{'nsRenewalUrl'})) {
         if($self->{$sect}->{'nsRenewalUrl'}
               =~ /ENV:/) {
            $self->{$sect}->{'nsRenewalUrl'} = 'user';
         }
      }else {
         $self->{$sect}->{'nsRenewalUrl'} = 'none';
      }
      
      # store extendedKeyUsage information
      if(defined($self->{$sect}->{'extendedKeyUsage'})) {
         if($self->{$sect}->{'extendedKeyUsage'} =~ /critical/) {
            $self->{$sect}->{'extendedKeyUsageType'} = 'critical';
            $self->{$sect}->{'extendedKeyUsage'} =~ s/critical\s*,\s*//;
         }else {
            $self->{$sect}->{'extendedKeyUsageType'} = 'noncritical';
         }
         if($self->{$sect}->{'extendedKeyUsage'} 
               =~ /ENV:/) {
            $self->{$sect}->{'extendedKeyUsage'} = 'user';
         }
      }else {
         $self->{$sect}->{'extendedKeyUsage'} = 'none';
         $self->{$sect}->{'extendedKeyUsageType'} = 'noncritical';
      }
      
      # store keyUsage information
      if(defined($self->{$sect}->{'keyUsage'})) {
         if($self->{$sect}->{'keyUsage'} =~ /critical/) {
            $self->{$sect}->{'keyUsageType'} = 'critical';
         }else {
            $self->{$sect}->{'keyUsageType'} = 'noncritical';
         }
         if($self->{$sect}->{'keyUsage'} 
               =~ /digitalSignature, keyEncipherment/) {
            $self->{$sect}->{'keyUsage'} = 'keysig';
         } elsif($self->{$sect}->{'keyUsage'}
               =~ /digitalSignature/) {
            $self->{$sect}->{'keyUsage'} = 'sig';
         } elsif($self->{$sect}->{'keyUsage'}
               =~ /keyEncipherment/) {
            $self->{$sect}->{'keyUsage'} = 'key';
         } elsif($self->{$sect}->{'keyUsage'}
               =~ /keyCertSign, cRLSign/) {
            $self->{$sect}->{'keyUsage'} = 'keyCertSign, cRLSign';
         } elsif($self->{$sect}->{'keyUsage'}
               =~ /keyCertSign/) {
            $self->{$sect}->{'keyUsage'} = 'keyCertSign';
         } elsif($self->{$sect}->{'keyUsage'}
               =~ /cRLSign/) {
            $self->{$sect}->{'keyUsage'} = 'cRLSign';
         }else {
            $self->{$sect}->{'keyUsage'} = 'none';
         }
      }else {
         $self->{$sect}->{'keyUsage'} = 'none';
         $self->{$sect}->{'keyUsageType'} = 'noncritical';
      }
   }

   # hack to add new section to openssl.cnf, if old config
   if(not defined($self->{'ca_ca'})) {
      $self->{'ca_ca'} = $self->{'server_ca'};
      $self->{'ca_ca'}->{'x509_extensions'} = "v3_ca";
      $self->{'server_ca'}->{'x509_extensions'} = "server_cert";

      $self->write_config($main, $ca);
   }
   if($self->{'server_ca'}->{'x509_extensions'} eq "v3_ca") {
      $self->{'server_ca'}->{'x509_extensions'} = "server_cert";
      $self->write_config($main, $ca);
   }

   # hack to add new option
   if(not defined($self->{'ca_ca'}->{'unique_subject'})) {
      $self->{'ca_ca'}->{'unique_subject'} = "yes";

      $self->write_config($main, $ca);
   }
   if(not defined($self->{'server_ca'}->{'unique_subject'})) {
      $self->{'server_ca'}->{'unique_subject'} = "yes";

      $self->write_config($main, $ca);
   }
   if(not defined($self->{'client_ca'}->{'unique_subject'})) {
      $self->{'client_ca'}->{'unique_subject'} = "yes";

      $self->write_config($main, $ca);
   }
   
   return;
}

sub config_ca {
   my ($self, $main, $ca) = @_;

   my($action);

   if(not defined($ca)) { 
      $ca = $main->{'CA'}->{'actca'};
   }
   if(not defined($ca)) {
      GUI::HELPERS::print_warning(_("Can't get CA name"));
   }

   $action = GUI::TCONFIG::show_config_ca($main, $ca);

   return;
}

sub config_openssl {
   my ($self, $main, $ca) = @_;

   if(not defined($ca)) { 
      $ca = $main->{'CA'}->{'actca'};
   }
   if(not defined($ca)) {
      GUI::HELPERS::print_warning(_("Can't get CA name"));
   }

   GUI::TCONFIG::show_configbox($main, $ca);

   return;
}

sub write_config {
   my ($self, $main, $ca) = @_;

   my($file, @sections, $line, $sect, $key, $val, @opts);

   # these sections are not configurable
   @sections = qw(
         ca 
         policy_client 
         policy_server 
         policy_ca
         req 
         req_distinguished_name 
         v3_req 
         req_attributes
         );

   $file = $main->{'CA'}->{$ca}->{'cnf'};

   open(OUT, ">$file") || do {
      GUI::HELPERS::print_warning(_("Can't open configfile"));
      return;
   };

   foreach $sect (@sections) {
      print OUT "[ $sect ]\n";
      foreach $line (@{$self->{$sect}}) {
         print OUT "$line\n";
      }
      print OUT "\n";
   }

   # these sections are configurable
   @sections = qw(
         v3_ca 
         crl_ext
         server_ca 
         client_ca 
         ca_ca 
         client_cert 
         server_cert
         );

   foreach $sect (@sections) {
      print OUT "[ $sect ]\n";
      if($sect eq "v3_ca") {
         @opts = qw( 
               subjectKeyIdentifier
               authorityKeyIdentifier
               basicConstraints
               nsCertType
               issuerAltName
               nsComment
               crlDistributionPoints
               nsCaRevocationUrl
               nsCaPolicyUrl
               nsRevocationUrl
               nsRenewalUrl
               );

         foreach $key (@opts) {
          if(defined($self->{$sect}->{$key}) && 
             $self->{$sect}->{$key}  ne '' &&
             $self->{$sect}->{$key}  ne 'none') {
             print OUT "$key = $self->{$sect}->{$key}\n";
          }
         }
         if(defined($self->{$sect}->{'subjectAltName'})) {
            if($self->{$sect}->{'subjectAltName'} eq 'emailcopy') {
               print OUT "subjectAltName = email:copy\n";
            } elsif($self->{$sect}->{'subjectAltName'} eq 'none') {
               ;# do nothing
            }
         }
         if(defined($self->{$sect}->{'keyUsage'})) {
            if($self->{$sect}->{'keyUsage'} eq 'keyCertSign') {
               if($self->{$sect}->{'keyUsageType'} eq 'critical') {
                  print OUT "keyUsage = critical, keyCertSign\n";
               } else {
                  print OUT "keyUsage = keyCertSign\n";
               }
            }elsif($self->{$sect}->{'keyUsage'} eq 'cRLSign') {
               if($self->{$sect}->{'keyUsageType'} eq 'critical') {
                  print OUT "keyUsage = critical, cRLSign\n";
               }else {
                  print OUT "keyUsage = cRLSign\n";
               }
            }elsif($self->{$sect}->{'keyUsage'} eq 'keyCertSign, cRLSign') {
               if($self->{$sect}->{'keyUsageType'} eq 'critical') {
                  print OUT "keyUsage = critical, keyCertSign, cRLSign\n";
               }else {
                  print OUT "keyUsage = keyCertSign, cRLSign\n";
               }
            }elsif($self->{$sect}->{'keyUsage'} eq 'none') {
               ;# do nothing
            }
         }
      } elsif($sect eq "server_cert" ||
              $sect eq "client_cert") {
         @opts = qw( 
               basicConstraints
               nsCertType
               nsComment
               subjectKeyIdentifier
               authorityKeyIdentifier
               issuerAltName
               crlDistributionPoints
               nsCaRevocationUrl
               nsBaseUrl
               nsCaPolicyUrl
               );

         foreach $key (@opts) {
          if(defined($self->{$sect}->{$key}) && 
             $self->{$sect}->{$key}  ne '' &&
             $self->{$sect}->{$key}  ne 'none') {
             print OUT "$key = $self->{$sect}->{$key}\n";
          }
         }
         if(defined($self->{$sect}->{'nsSslServerName'})) {
            if($self->{$sect}->{'nsSslServerName'} eq 'user') {
               print OUT "nsSslServerName = \$ENV::NSSSLSERVERNAME\n";
            } elsif($self->{$sect}->{'nsSslServerName'} eq 'none') {
               ;# do nothing
            } 
         }
         if(defined($self->{$sect}->{'nsRevocationUrl'})) {
            if($self->{$sect}->{'nsRevocationUrl'} eq 'user') {
               print OUT "nsRevocationUrl = \$ENV::NSREVOCATIONURL\n";
            } elsif($self->{$sect}->{'nsRevocationUrl'} eq 'none') {
               ;# do nothing
            } 
         }
         if(defined($self->{$sect}->{'nsRenewalUrl'})) {
            if($self->{$sect}->{'nsRenewalUrl'} eq 'user') {
               print OUT "nsRenewalUrl = \$ENV::NSRENEWALURL\n";
            } elsif($self->{$sect}->{'nsRenewalUrl'} eq 'none') {
               ;# do nothing
            } 
         }
         if(defined($self->{$sect}->{'subjectAltName'})) {
            if($self->{$sect}->{'subjectAltName'} eq 'user') {
               if($self->{$sect}->{'subjectAltNameType'} eq 'ip') {
                  print OUT "subjectAltName = \$ENV::SUBJECTALTNAMEIP\n";
               } elsif($self->{$sect}->{'subjectAltNameType'} eq 'dns') {
                  print OUT "subjectAltName = \$ENV::SUBJECTALTNAMEDNS\n";
               } elsif($self->{$sect}->{'subjectAltNameType'} eq 'mail') {
                  print OUT "subjectAltName = \$ENV::SUBJECTALTNAMEEMAIL\n";
               } elsif($self->{$sect}->{'subjectAltNameType'} eq 'raw') {
                  print OUT "subjectAltName = \$ENV::SUBJECTALTNAMERAW\n";
               }
            } elsif($self->{$sect}->{'subjectAltName'} eq 'emailcopy') {
               print OUT "subjectAltName = email:copy\n";
            } elsif($self->{$sect}->{'subjectAltName'} eq 'none') {
               ;# do nothing
            }
         }
         if(defined($self->{$sect}->{'keyUsage'})) {
            if($self->{$sect}->{'keyUsage'} eq 'key') {
               if($self->{$sect}->{'keyUsageType'} eq 'critical') {
                  print OUT "keyUsage = critical, keyEncipherment\n";
               } else {
                  print OUT "keyUsage = keyEncipherment\n";
               }
            }elsif($self->{$sect}->{'keyUsage'} eq 'sig') {
               if($self->{$sect}->{'keyUsageType'} eq 'critical') {
                  print OUT "keyUsage = critical, digitalSignature\n";
               }else {
                  print OUT "keyUsage = digitalSignature\n";
               }
            }elsif($self->{$sect}->{'keyUsage'} eq 'keysig') {
               if($self->{$sect}->{'keyUsageType'} eq 'critical') {
                  print OUT "keyUsage = critical, digitalSignature, keyEncipherment\n";
               }else {
                  print OUT "keyUsage = digitalSignature, keyEncipherment\n";
               }
            }elsif($self->{$sect}->{'keyUsage'} eq 'none') {
               ;# do nothing
            }
         }
         if(defined($self->{$sect}->{'extendedKeyUsage'})) {
            if(($self->{$sect}->{'extendedKeyUsage'} ne 'none') &&
               ($self->{$sect}->{'extendedKeyUsage'} ne '')) {
               if($self->{$sect}->{'extendedKeyUsage'} eq 'user') {
                 if($self->{$sect}->{'extendedKeyUsageType'} eq 'critical') {
                     print OUT "extendedKeyUsage = critical, \$ENV::EXTENDEDKEYUSAGE\n";
                 } else {
                     print OUT "extendedKeyUsage = \$ENV::EXTENDEDKEYUSAGE\n";
                 }
               } else { 
                  if($self->{$sect}->{'extendedKeyUsageType'} eq 'critical') { 
                     print OUT "extendedKeyUsage = critical, $self->{$sect}->{'extendedKeyUsage'}\n";
                  } else {
                     print OUT "extendedKeyUsage = $self->{$sect}->{'extendedKeyUsage'}\n";
                  }
               }
           } elsif ($self->{$sect}->{'extendedKeyUsage'} eq 'none') {
              ;# do nothing
           }
         }
      } elsif(($sect eq "server_ca") ||
              ($sect eq "client_ca") ||
              ($sect eq "ca_ca")) {
         @opts = qw( 
               dir
               certs
               crl_dir
               database
               new_certs_dir
               certificate
               serial
               crl
               private_key
               RANDFILE
               x509_extensions
               default_days
               default_crl_days
               default_md
               preserve
               policy
               unique_subject
               );

         foreach $key (@opts) {
          if(defined($self->{$sect}->{$key}) && 
             $self->{$sect}->{$key}  ne '' &&
             $self->{$sect}->{$key}  ne 'none') {
             print OUT "$key = $self->{$sect}->{$key}\n";
          }
         }
      } else {
         while(($key, $val) = each(%{$self->{$sect}})) {
            if(defined($val) && $val ne "") {
             print OUT "$key = $val\n";
            }
         }
      }
      print OUT "\n";
   }

   close OUT;

#   print STDERR "DEBUG: wrote config and reinit\n";
#   $self->init_config($main, $ca);

   return;
}
   
1
