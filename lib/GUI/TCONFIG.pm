# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: TCONFIG.pm,v 1.6 2006/06/28 21:50:42 sm Exp $
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
package GUI::TCONFIG;

use POSIX;

#
# main screen for configuration
#
sub show_configbox {
   my ($main, $name) = @_;

   my ($box, $vbox, $label, $table, $rows, @options, @options_ca, $entry,
         $key, $separator, $t, @combostrings, $button_cancel,
         $button_help, $buttonbox,
         $combonsCertType, $combosubjectAltName, $combokeyUsage,
         $comboextendedKeyUsage, $combonsSslServer, $combonsRevocationUrl,
         $combonsRenewalUrl,
         $combocnsCertType, $combocsubjectAltName, $combockeyUsage,
         $combocextendedKeyUsage, $combocnsSslServer, $combocnsRevocationUrl,
         $combocnsRenewalUrl,
         $combocansCertType, $combocasubjectAltName, $combocakeyUsage,
         $combocaextendedKeyUsage, $combocansSslServer, $combocansRevocationUrl,
         $combocansRenewalUrl);

   if(not defined($name)) {
      $name = $main->{'CA'}->{'actca'};
   }
   if(not defined($name)) {
      GUI::HELPERS::print_warning(_("Can't get CA name"));
      return;
   }

   $main->{'TCONFIG'}->init_config($main, $name);

   $box = Gtk2::Window->new("toplevel");
   $box->set_title("OpenSSL Configuration");
   $box->set_resizable(1);
   $box->set_default_size(800, 600);
   $box->signal_connect('delete_event' => sub { $box->destroy() });

   $box->{'button_ok'} = Gtk2::Button->new_from_stock('gtk-ok');
   $box->{'button_ok'}->set_sensitive(0);
   $box->{'button_ok'}->signal_connect('clicked' => 
      sub { $main->{'TCONFIG'}->write_config($main, $name);
            $box->destroy() });


   $box->{'button_apply'} = Gtk2::Button->new_from_stock('gtk-apply');
   $box->{'button_apply'}->set_sensitive(0);
   $box->{'button_apply'}->signal_connect('clicked' => 
      sub { $main->{'TCONFIG'}->write_config($main, $name) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect( 'clicked' => sub { $box->destroy() });

   $t = _("All Settings are written unchanged to openssl.conf.\nSo please study the documentation of OpenSSL if you don't know exactly what to do.\nIf you are still unsure - keep the defaults and everything is expected to work fine.");
   $button_help = Gtk2::Button->new_from_stock('gtk-help');
   $button_help->signal_connect('clicked' => 
      sub { GUI::HELPERS::print_info($t) });

   $box->{'vbox'} = Gtk2::VBox->new();

   $box->{'nb'} = Gtk2::Notebook->new();
   $box->{'nb'}->set_tab_pos('top');
   $box->{'nb'}->set_show_tabs(1);
   $box->{'nb'}->set_show_border(1);
   $box->{'nb'}->set_scrollable(0);

   $box->add($box->{'vbox'});

   $box->{'vbox'}->pack_start($box->{'nb'}, 1, 1, 0);

   $buttonbox = Gtk2::HButtonBox->new();
   $buttonbox->set_layout('end');
   $buttonbox->set_spacing(3);
   $buttonbox->set_border_width(3);
   $buttonbox->add($button_help);
   $buttonbox->set_child_secondary($button_help, 1);

   $buttonbox->add($box->{'button_ok'});
   $buttonbox->add($box->{'button_apply'});
   $buttonbox->add($button_cancel);

   $box->{'vbox'}->pack_start($buttonbox, 0, 0, 0);

   # first page: vbox with warnings :-)
   $vbox = Gtk2::VBox->new(0, 0);

   $label = GUI::HELPERS::create_label(
         _("OpenSSL Configuration"), 'center', 0,0);

   $box->{'nb'}->append_page($vbox, $label);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("OpenSSL Configuration"), 'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk2::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Only change these options, if you really know, what you are doing!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("You should be aware, that some options may break some crappy software!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);


   $label = GUI::HELPERS::create_label(
         _("If you are unsure: leave the defaults untouched"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   # second page: server settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   my @special_options = qw(
         nsCertType
         nsSslServerName
         nsRevocationUrl
         nsRenewalUrl
         subjectAltName
         keyUsage
         extendedkeyUsage
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk2::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating Server Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk2::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk2::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(_("Server Certificate Settings"), 
         'center', 0, 0);
   $label = Gtk2::Label->new(_("Server Certificate Settings"));

   $box->{'nb'}->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);
   $main->{'radio1'} = Gtk2::RadioButton->new(
         undef, _($main->{'words'}{'ip'}));
   $main->{'radio1'}->signal_connect('toggled' =>
        sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
           \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}, 'ip',
           $box)});

   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new(
         $main->{'radio1'}, _($main->{'words'}{'dns'}));
   $main->{'radio2'}->signal_connect('toggled' =>
        sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
           \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'},
           'dns', $box)});

   $main->{'radiobox'}->add($main->{'radio2'});

   $main->{'radio3'} = Gtk2::RadioButton->new($main->{'radio1'},
         _($main->{'words'}{'raw'}));

   $main->{'radio3'}->signal_connect('toggled' =>
        sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio3'},
           \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'},
           'raw', $box)});

   $main->{'radiobox'}->add($main->{'radio3'});

   if($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
         eq 'ip') {
      $main->{'radio1'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
         eq 'dns') {
      $main->{'radio2'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
         eq 'raw') {
      $main->{'radio3'}->set_active(1)
   }

   $combosubjectAltName = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'user'}, 
         $main->{'words'}{'emailcopy'});
   $combosubjectAltName->set_popdown_strings(@combostrings);
   $combosubjectAltName->set_use_arrows(1);
   $combosubjectAltName->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'user') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);
        $main->{'radio3'}->set_sensitive(1);

        $combosubjectAltName->entry->set_text($main->{'words'}{'user'});
     }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $combosubjectAltName->entry->set_text($main->{'words'}{'emailcopy'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
     }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'none') { 
        $combosubjectAltName->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
     }
   } else { 
      $combosubjectAltName->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
      $main->{'radio3'}->set_sensitive(0);
   }
   $combosubjectAltName->entry->signal_connect('changed' => 
         sub { GUI::CALLBACK::entry_to_var_san(
         $combosubjectAltName,
         $combosubjectAltName->entry, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}, 
         $box, 
         $main->{words}, 
         $main->{'radio1'},  
         $main->{'radio2'},
         $main->{'radio3'})});
   $table->attach_defaults($combosubjectAltName, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);

   $main->{'radio1'} = Gtk2::RadioButton->new(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' => 
         sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'},
            'critical', $box)});
         
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'},
            'noncritical', $box)});

   $main->{'radiobox'}->add($main->{'radio2'});

   $combokeyUsage = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'sig'}, 
         $main->{'words'}{'key'}, 
         $main->{'words'}{'keysig'});
   $combokeyUsage->set_popdown_strings(@combostrings);
   $combokeyUsage->set_use_arrows(1);
   $combokeyUsage->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'sig') {
           $combokeyUsage->entry->set_text($main->{'words'}{'sig'});
        }elsif($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'key') {
           $combokeyUsage->entry->set_text($main->{'words'}{'key'});
        }elsif($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'keysig') {
           $combokeyUsage->entry->set_text($main->{'words'}{'keysig'});
        }else {
           $combokeyUsage->entry->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combokeyUsage->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combokeyUsage->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combokeyUsage->entry->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var_key($combokeyUsage, $combokeyUsage->entry,
            \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'})});

   $table->attach_defaults($combokeyUsage, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option extendedKeyUsage
   $label = GUI::HELPERS::create_label(
         _("Extended Key Usage (extendedKeyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);
   $main->{'radio1'} = Gtk2::RadioButton->new(undef, 
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'},
            'critical', $box)});
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new($main->{'radio1'}, 
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'},
            'noncritical', $box)});
   $main->{'radiobox'}->add($main->{'radio2'});

   $comboextendedKeyUsage = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'user'});
   
   if((defined($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'})) &&
      ($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} ne 'none') &&
      ($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} ne '')) {
      push(@combostrings, 
            $main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'});
   }
   
   $comboextendedKeyUsage->set_popdown_strings(@combostrings);
   $comboextendedKeyUsage->set_use_arrows(1);
   $comboextendedKeyUsage->set_value_in_list(0, 0);

   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} eq 'user'){
           $comboextendedKeyUsage->entry->set_text($main->{'words'}{'user'});
        } else {
           $comboextendedKeyUsage->entry->set_text($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'});
        }
     } else {
        $comboextendedKeyUsage->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $comboextendedKeyUsage->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $comboextendedKeyUsage->entry->signal_connect('changed' => 
         sub { GUI::CALLBACK::entry_to_var_key($comboextendedKeyUsage, $comboextendedKeyUsage->entry,
            \$main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'}) });

   $table->attach_defaults($comboextendedKeyUsage, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combonsCertType = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'server'},
         $main->{'words'}{'server, client'});

   $combonsCertType->set_popdown_strings(@combostrings);
   $combonsCertType->set_use_arrows(1);
   $combonsCertType->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'})) {
      $combonsCertType->entry->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}});
   } else {
      $combonsCertType->entry->set_text($main->{'words'}{'none'});
   }
   $combonsCertType->entry->signal_connect('changed' => 
         sub { GUI::CALLBACK::entry_to_var($combonsCertType, $combonsCertType->entry,
            \$main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}, $box,
            $main->{words}) });

   $table->attach_defaults($combonsCertType, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsSslServer
   $label = GUI::HELPERS::create_label(
         _("Netscape SSL Server Name (nsSslServerName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combonsSslServer = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combonsSslServer->set_popdown_strings(@combostrings);
   $combonsSslServer->set_use_arrows(1);
   $combonsSslServer->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}) && 
         $main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'} 
         eq 'user') { 
      $combonsSslServer->entry->set_text($main->{'words'}{'user'});
   } else {
      $combonsSslServer->entry->set_text($main->{'words'}{'none'});
   }
   $combonsSslServer->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combonsSslServer, $combonsSslServer->entry,
           \$main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}, $box,
           $main->{words}) });

   $table->attach_defaults($combonsSslServer, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combonsRevocationUrl = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combonsRevocationUrl->set_popdown_strings(@combostrings);
   $combonsRevocationUrl->set_use_arrows(1);
   $combonsRevocationUrl->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}) && 
         $main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combonsRevocationUrl->entry->set_text($main->{'words'}{'user'});
   } else {
      $combonsRevocationUrl->entry->set_text($main->{'words'}{'none'});
   }
   $combonsRevocationUrl->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combonsRevocationUrl, $combonsRevocationUrl->entry,
           \$main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}, $box,
           $main->{words}) });

   $table->attach_defaults($combonsRevocationUrl, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRenewalUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combonsRenewalUrl = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combonsRenewalUrl->set_popdown_strings(@combostrings);
   $combonsRenewalUrl->set_use_arrows(1);
   $combonsRenewalUrl->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}) && 
         $main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'} 
         eq 'user') { 
      $combonsRenewalUrl->entry->set_text($main->{'words'}{'user'});
   } else {
      $combonsRenewalUrl->entry->set_text($main->{'words'}{'none'});
   }
   $combonsRenewalUrl->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combonsRenewalUrl, $combonsRenewalUrl->entry,
           \$main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}, $box,
           $main->{words}) });

   $table->attach_defaults($combonsRenewalUrl, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_cert'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   # third page: client settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk2::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating Client Certificates"), 
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk2::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk2::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(_("Client Certificate Settings"),
         'center', 0, 0);
   $box->{'nb'}->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);
   $main->{'radio1'} = Gtk2::RadioButton->new(undef, 
         _($main->{'words'}{'ip'}));
   $main->{'radio1'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'ip', $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new($main->{'radio1'},
         _($main->{'words'}{'dns'}));
   $main->{'radio2'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'dns', $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $main->{'radio3'} = Gtk2::RadioButton->new($main->{'radio1'},
         _($main->{'words'}{'mail'}));
   $main->{'radio3'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio3'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'mail', $box) });
   $main->{'radiobox'}->add($main->{'radio3'});

   $main->{'radio4'} = Gtk2::RadioButton->new($main->{'radio1'}, 
         _($main->{'words'}{'raw'}));
   $main->{'radio4'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio4'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'raw', $box) });
   $main->{'radiobox'}->add($main->{'radio4'});

   if($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'ip') {
      $main->{'radio1'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'dns') {
      $main->{'radio2'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'mail') {
      $main->{'radio3'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'raw') {
      $main->{'radio4'}->set_active(1)
   }

   $combocsubjectAltName = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'user'}, 
         $main->{'words'}{'emailcopy'});
   $combocsubjectAltName->set_popdown_strings(@combostrings);
   $combocsubjectAltName->set_use_arrows(1);
   $combocsubjectAltName->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'user') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);
        $main->{'radio3'}->set_sensitive(1);
        $main->{'radio4'}->set_sensitive(1);

        $combocsubjectAltName->entry->set_text($main->{'words'}{'user'});
     }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
        $main->{'radio4'}->set_sensitive(1);

        $combocsubjectAltName->entry->set_text($main->{'words'}{'emailcopy'});
     }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'none') { 
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
        $main->{'radio4'}->set_sensitive(1);

        $combocsubjectAltName->entry->set_text($main->{'words'}{'none'});
     }
   } else { 
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
      $main->{'radio3'}->set_sensitive(0);
      $main->{'radio4'}->set_sensitive(1);

      $combocsubjectAltName->entry->set_text($main->{'words'}{'none'});
   }
   $combocsubjectAltName->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var_san($combocsubjectAltName, $combocsubjectAltName->entry,
           \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}, $box,
           $main->{words}, $main->{'radio1'}, $main->{'radio2'},
           $main->{'radio3'}, $main->{'radio4'}) });
   $table->attach_defaults($combocsubjectAltName, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);
   $main->{'radio1'} = Gtk2::RadioButton->new(undef, 
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'},
            'critical', $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new($main->{'radio1'}, 
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'},
            'noncritical', $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $combockeyUsage = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'sig'}, 
         $main->{'words'}{'key'}, 
         $main->{'words'}{'keysig'});
   $combockeyUsage->set_popdown_strings(@combostrings);
   $combockeyUsage->set_use_arrows(1);
   $combockeyUsage->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'sig') {
           $combockeyUsage->entry->set_text($main->{'words'}{'sig'});
        }elsif($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'key') {
           $combockeyUsage->entry->set_text($main->{'words'}{'key'});
        }elsif($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'keysig') {
           $combockeyUsage->entry->set_text($main->{'words'}{'keysig'});
        }else {
           $combockeyUsage->entry->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combockeyUsage->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combockeyUsage->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combockeyUsage->entry->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var_key($combockeyUsage, $combockeyUsage->entry,
            \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'}) });
   $table->attach_defaults($combockeyUsage, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option extendedKeyUsage
   $label = GUI::HELPERS::create_label(
         _("Extended Key Usage (extendedKeyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);
   $main->{'radio1'} = Gtk2::RadioButton->new(undef, 
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'},
            'critical', $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new($main->{'radio1'}, 
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref( $main->{'radio2'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'},
            'noncritical', $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $combocextendedKeyUsage = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'user'});
   
   if((defined($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'})) &&
      ($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} ne 'none') &&
      ($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} ne '')) {
      push(@combostrings, 
            $main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'});
   }
   
   $combocextendedKeyUsage->set_popdown_strings(@combostrings);
   $combocextendedKeyUsage->set_use_arrows(1);
   $combocextendedKeyUsage->set_value_in_list(0, 0);

   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} eq 'user'){
           $combocextendedKeyUsage->entry->set_text($main->{'words'}{'user'});
        } else {
           $combocextendedKeyUsage->entry->set_text($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'});
        }
     } else {
        $combocextendedKeyUsage->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combocextendedKeyUsage->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combocextendedKeyUsage->entry->signal_connect('changed' => 
         sub { GUI::CALLBACK::entry_to_var_key($combocextendedKeyUsage, $combocextendedKeyUsage->entry,
            \$main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'}) });
   $table->attach_defaults($combocextendedKeyUsage, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combocnsCertType = Gtk2::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'objsign'}, 
         $main->{'words'}{'email'}, 
         $main->{'words'}{'client'}, 
         $main->{'words'}{'client, email'}, 
         $main->{'words'}{'client, objsign'},
         $main->{'words'}{'client, email, objsign'});
   $combocnsCertType->set_popdown_strings(@combostrings);
   $combocnsCertType->set_use_arrows(1);
   $combocnsCertType->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'})) {
      $combocnsCertType->entry->set_text( 
            $main->{'words'}{$main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}});
   } else {
      $combocnsCertType->entry->set_text($main->{'words'}{'none'});
   }
   $combocnsCertType->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocnsCertType, $combocnsCertType->entry,
           \$main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}, $box,
           $main->{words}) });
   $table->attach_defaults($combocnsCertType, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combocnsRevocationUrl = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combocnsRevocationUrl->set_popdown_strings(@combostrings);
   $combocnsRevocationUrl->set_use_arrows(1);
   $combocnsRevocationUrl->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}) && 
         $main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combocnsRevocationUrl->entry->set_text($main->{'words'}{'user'});
   } else {
      $combocnsRevocationUrl->entry->set_text($main->{'words'}{'none'});
   }
   $combocnsRevocationUrl->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocnsRevocationUrl, $combocnsRevocationUrl->entry,
           \$main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}, $box,
           $main->{words}) });
   $table->attach_defaults($combocnsRevocationUrl, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRenewalUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combocnsRenewalUrl = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combocnsRenewalUrl->set_popdown_strings(@combostrings);
   $combocnsRenewalUrl->set_use_arrows(1);
   $combocnsRenewalUrl->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}) && 
         $main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'} 
         eq 'user') { 
      $combocnsRenewalUrl->entry->set_text($main->{'words'}{'user'});
   } else {
      $combocnsRenewalUrl->entry->set_text($main->{'words'}{'none'});
   }
   $combocnsRenewalUrl->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocnsRenewalUrl, $combocnsRenewalUrl->entry,
           \$main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}, $box,
           $main->{words}) });
   $table->attach_defaults($combocnsRenewalUrl, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'client_cert'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'client_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   # fourth page: ca settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   @special_options = qw(
         nsCertType
         nsRevocationUrl
         subjectAltName
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk2::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating CA Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk2::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk2::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(_("CA Certificate Settings"), 
         'center', 0, 0);
   $label = Gtk2::Label->new(_("CA Certificate Settings"));

   $box->{'nb'}->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combocasubjectAltName = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'emailcopy'});
   $combocasubjectAltName->set_popdown_strings(@combostrings);
   $combocasubjectAltName->set_use_arrows(1);
   $combocasubjectAltName->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $combocasubjectAltName->entry->set_text($main->{'words'}{'emailcopy'});
     }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'none') { 
        $combocasubjectAltName->entry->set_text($main->{'words'}{'none'});
     }
   } else { 
      $combocasubjectAltName->entry->set_text($main->{'words'}{'none'});
   }
   $combocasubjectAltName->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var_san($combocasubjectAltName,
         $combocasubjectAltName->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}, 
         $box, $main->{words}) });
   $table->attach_defaults($combocasubjectAltName, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combocansCertType = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, 
                    $main->{'words'}{'emailCA'},
                    $main->{'words'}{'sslCA'},
                    $main->{'words'}{'objCA'},
                    $main->{'words'}{'sslCA, emailCA'},
                    $main->{'words'}{'sslCA, objCA'},
                    $main->{'words'}{'emailCA, objCA'},
                    $main->{'words'}{'sslCA, emailCA, objCA'} 
                    );
   $combocansCertType->set_popdown_strings(@combostrings);
   $combocansCertType->set_use_arrows(1);
   $combocansCertType->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'})) {
      $combocansCertType->entry->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}});
   } else {
      $combocansCertType->entry->set_text($main->{'words'}{'none'});
   }
   $combocansCertType->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocansCertType, $combocansCertType->entry,
           \$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}, $box,
           $main->{words}) });
   $table->attach_defaults($combocansCertType, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);
   $main->{'radio1'} = Gtk2::RadioButton->new(undef, 
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'critical',
            $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new($main->{'radio1'}, 
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'noncritical',
            $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $combocakeyUsage = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, 
                    $main->{'words'}{'keyCertSign'}, 
                    $main->{'words'}{'cRLSign'}, 
                    $main->{'words'}{'keyCertSign, cRLSign'});
   $combocakeyUsage->set_popdown_strings(@combostrings);
   $combocakeyUsage->set_use_arrows(1);
   $combocakeyUsage->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'keyCertSign') {
           $combocakeyUsage->entry->set_text($main->{'words'}{'keyCertSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'cRLSign') {
           $combocakeyUsage->entry->set_text($main->{'words'}{'cRLSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 
                                                 'keyCertSign, cRLSign') {
           $combocakeyUsage->entry->set_text($main->{'words'}{'keyCertSign, cRLSign'});
        }else {
           $combocakeyUsage->entry->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combocakeyUsage->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combocakeyUsage->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combocakeyUsage->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var_key($combocakeyUsage, $combocakeyUsage->entry,
           \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'}, $box, $main->{words},
           $main->{'radio1'},  $main->{'radio2'}) });
   $table->attach_defaults($combocakeyUsage, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combocansRevocationUrl = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combocansRevocationUrl->set_popdown_strings(@combostrings);
   $combocansRevocationUrl->set_use_arrows(1);
   $combocansRevocationUrl->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}) && 
         $main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combocansRevocationUrl->entry->set_text($main->{'words'}{'user'});
   } else {
      $combocansRevocationUrl->entry->set_text($main->{'words'}{'none'});
   }
   $combocansRevocationUrl->entry->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocansRevocationUrl, $combocansRevocationUrl->entry,
           \$main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}, $box,
           $main->{words}) });
   $table->attach_defaults($combocansRevocationUrl, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'v3_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'ca_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   # fifth page: crl settings
   @options = qw(
         default_crl_days
         );

   $vbox = Gtk2::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating Certificate Revocation Lists"), 
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk2::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk2::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Revocation List Settings"), 'center', 0, 0);
   $box->{'nb'}->append_page($vbox, $label);

   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   $box->show_all();

   $box->{'button_ok'}->set_sensitive(0);
   $box->{'button_apply'}->set_sensitive(0);

   return;
}

#
# configuration for CA
#
sub show_config_ca {
   my ($main, $opts, $mode) = @_;

   my(@options, $key, $box, $button_ok, $button_cancel, $table, $label,
         $entry, $rows, @combostrings, $combonsCertType, $combosubjectAltName,
         $combokeyUsage);

   @options = qw(
         authorityKeyIdentifier
         basicConstraints
         issuerAltName
         nsComment
         nsCaRevocationUrl
         nsCaPolicyUrl
         nsRevocationUrl
         nsPolicyUrl
         );
   
   if(not defined($opts->{'name'})) {
      GUI::HELPERS::print_warning(_("Can't get CA name"));
      return;
   }

   $main->{'TCONFIG'}->init_config($main, $opts->{'name'});

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);

   $button_ok->signal_connect('clicked', 
         sub { 
            $main->{'TCONFIG'}->write_config($main, $opts->{'name'});
            $opts->{'configured'} = 1;
            $main->{'CA'}->create_ca($main, $opts, $box, $mode) });


   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("CA Configuration"), _("CA Configuration"), 
         $button_ok, $button_cancel);


   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating this CA Certificate"), 
         'center', 0, 1);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("and the CA Certificates of every SubCA, created with this CA."),
         'center', 0, 1);
   $box->vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("If you are unsure: leave the defaults untouched"), 
         'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk2::Table->new($rows, 2, 0);
   $box->vbox->add($table);

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk2::HBox->new(0, 0);
   $main->{'radio1'} = Gtk2::RadioButton->new(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' =>
         sub{ GUI::CALLBACK::toggle_to_var_pref( $main->{'radio1'}, 
            \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'critical')});
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk2::RadioButton->new($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
         \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'noncritical')});
   $main->{'radiobox'}->add($main->{'radio2'});

   $combokeyUsage = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, 
                    $main->{'words'}{'keyCertSign'}, 
                    $main->{'words'}{'cRLSign'}, 
                    $main->{'words'}{'keyCertSign, cRLSign'});
   $combokeyUsage->set_popdown_strings(@combostrings);
   $combokeyUsage->set_use_arrows(1);
   $combokeyUsage->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} 
        ne 'none') { 
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'keyCertSign') {
           $combokeyUsage->entry->set_text($main->{'words'}{'keyCertSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'cRLSign') {
           $combokeyUsage->entry->set_text($main->{'words'}{'cRLSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 
                                                 'keyCertSign, cRLSign') {
           $combokeyUsage->entry->set_text($main->{'words'}{'keyCertSign, cRLSign'});
        }else {
           $combokeyUsage->entry->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combokeyUsage->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combokeyUsage->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combokeyUsage->entry->signal_connect('changed' =>
         sub{&GUI::CALLBACK::entry_to_var_key($combokeyUsage, 
            $combokeyUsage->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'}, 
         undef, $main->{words}, $main->{'radio1'},  $main->{'radio2'})});
   $table->attach_defaults($combokeyUsage, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combonsCertType = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, 
                    $main->{'words'}{'emailCA'},
                    $main->{'words'}{'sslCA'},
                    $main->{'words'}{'objCA'},
                    $main->{'words'}{'sslCA, emailCA'},
                    $main->{'words'}{'sslCA, objCA'},
                    $main->{'words'}{'emailCA, objCA'},
                    $main->{'words'}{'sslCA, emailCA, objCA'} 
                    );
   $combonsCertType->set_popdown_strings(@combostrings);
   $combonsCertType->set_use_arrows(1);
   $combonsCertType->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'})) {
      $combonsCertType->entry->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}});
   } else {
      $combonsCertType->entry->set_text($main->{'words'}{'none'});
   }
   $combonsCertType->entry->signal_connect('changed' =>
         sub{GUI::CALLBACK::entry_to_var($combonsCertType, 
         $combonsCertType->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}, 
         undef, $main->{words})});
   $table->attach_defaults($combonsCertType, 1, 2, $rows-1, $rows);
   $rows++;

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combosubjectAltName = Gtk2::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'emailcopy'});
   $combosubjectAltName->set_popdown_strings(@combostrings);
   $combosubjectAltName->set_use_arrows(1);
   $combosubjectAltName->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $combosubjectAltName->entry->set_text($main->{'words'}{'emailcopy'});
     }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'none') { 
        $combosubjectAltName->entry->set_text($main->{'words'}{'none'});
     }
   } else { 
      $combosubjectAltName->entry->set_text($main->{'words'}{'none'});
   }
   $combosubjectAltName->entry->signal_connect('changed' =>
         sub{GUI::CALLBACK::entry_to_var_san($combosubjectAltName,
         $combosubjectAltName->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}, 
         undef, $main->{words})});
   $table->attach_defaults($combosubjectAltName, 1, 2, $rows-1, $rows);
   $rows++;

   foreach $key (@options) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'v3_ca'}->{$key}, $table, $rows-1, 1);

      $rows++;
      $table->resize($rows, 2);
   }

   $box->show_all();

   return;
}

1
