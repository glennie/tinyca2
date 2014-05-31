# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: GUI.pm,v 1.34 2006/07/25 20:10:54 sm Exp $
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
package GUI;

use POSIX;

use Gtk2::SimpleMenu;

my $false=undef;
my $true=1;

# This hash maps our internal MD names to the displayed digest names.
# Maybe it should live in a crypto-related file instead of a UI-related file?
my %md_algorithms = (
		     'md5' => 'MD5',
		     'sha1' => 'SHA1',
		     'md2' => 'MD2',
		     'mdc2' => 'MDC2',
		     'md4' => 'MD4',
		     'ripemd160' => 'RIPEMD-160',
#		     'sha' => 'SHA',
		     'sha1' => 'SHA-1',
		     );

my %bit_lengths = (
		     '1024' => '1024',
		     '2048' => '2048',
		     '4096' => '4096'
		     );


#
# create the main object
#
sub new {
   my $that = shift;
   my $class = ref($that) || $that;

   my $self = {};
   $self->{'init'} = shift;

   bless($self, $class);

   $self->{'version'} = '0.7.5';

   $self->{'words'} = GUI::WORDS->new();

   $self->{'exportdir'}        = $self->{'init'}->{'exportdir'};
   $self->{'basedir'}          = $self->{'init'}->{'basedir'};
   $self->{'tmpdir'}           = $self->{'basedir'}."/tmp";
   $self->{'init'}->{'tmpdir'} = $self->{'basedir'}."/tmp";

   # initialize CA object
   $self->{'CA'} = CA->new($self->{'init'});

   # initialize OpenSSL object
   $self->{'OpenSSL'} = OpenSSL->new($self->{'init'}->{'opensslbin'},
				     $self->{'tmpdir'});

   # initialize CERT object
   $self->{'CERT'} = CERT->new($self->{'OpenSSL'});

   # initialize KEY object
   $self->{'KEY'} = KEY->new();

   # initialize REQ object
   $self->{'REQ'} = REQ->new($self->{'OpenSSL'});

   # initialize CONFIG object
   $self->{'TCONFIG'} = TCONFIG->new();

   # initialize fonts and styles
   $self->{'fontfix'} = Gtk2::Pango::FontDescription->from_string(
         "Courier 10"
         );

#   Gtk::Rc->parse_string(
#'style "default"
#{
#  fontset = "-*-helvetica-medium-r-normal--11-*,-*-fixed-medium-r-normal--11-*"
#}
#widget_class "*" style "default"');

#   $self->{'stylered'} = Gtk2::Style->new();
#   $self->{'stylered'}->fg('normal', Gtk2::Gdk::Color->parse('red'));

#   $self->{'stylegreen'} = Gtk2::Style->new();
#   $self->{'stylegreen'}->fg('normal', Gtk2::Gdk::Color->parse('green'));

   # initialize main window
   $self->{'mw'} = Gtk2::Window->new("toplevel");
   $self->{'mw'}->set_title("TinyCA2 Management $self->{'version'}");

   $self->{'mw'}->set_resizable(1);
   $self->{'mw'}->set_default_size(850, 600);
   $self->{'mw'}->signal_connect( 'delete_event', 
         sub { HELPERS::exit_clean(0) });

   $self->{'busycursor'} = Gtk2::Gdk::Cursor->new('watch');
   $self->{'cursor'}     = Gtk2::Gdk::Cursor->new('left-ptr');
   $self->{'rootwin'}    = Gtk2::Gdk->get_default_root_window();

   # split window horizontal to add menu, toolbar and notebook
   $self->{'mvb'} = Gtk2::VBox->new();
   $self->{'mw'}->add($self->{'mvb'});

   $self->create_menu();
   $self->{'mvb'}->pack_start($self->{'menu'}->{'widget'} , 0, 0, 0);

   $self->create_toolbar('startup');
   $self->{'mvb'}->pack_start($self->{'toolbar'}, 0, 0, 0);
   
   $self->create_nb();
   $self->{'sizebox'} = Gtk2::VBox->new();
   $self->{'mvb'}->pack_start($self->{'sizebox'}, 1, 1, 0);
   $self->{'sizebox'}->pack_start($self->{'nb'}, 1, 1, 0);

   $self->create_bar();
   $self->{'mvb'}->pack_start($self->{'barbox'}, 0, 0, 0);

   $self->{'rootwin'}->set_cursor($self->{'cursor'});

   $self;
}

#
# create/update the main frame with the notebooks
#
sub create_mframe {
   my ($self, $force) = @_;

   my($parsed, $calabel, $caframe, $rows, $table, @fields, $text, @childs,
         $label, $cert_export, $cert_revoke, $cert_delete, $certlabel,
         $certlistwin, @certtitles, @keytitles, $keylabel, $keylistwin,
         $reqlistwin, @reqtitles, $reqlabel, $ind, $column, $ca, $cadir);

   if ((defined($self->{'CA'}->{'actca'})) &&
       ($self->{'CA'}->{'actca'} ne "")) {
      $ca = $self->{'CA'}->{'actca'};
   } else {
      return;
   }

   $cadir = $self->{'CA'}->{'cadir'};

   $parsed = $self->{'CERT'}->parse_cert( $self, 'CA');

   defined($parsed) || 
      GUI::HELPERS::print_error( _("Can't read CA certificate"));

   ### notebooktab for ca information
   if(not defined($self->{'cabox'})) {
      $self->{'cabox'} = Gtk2::VBox->new(0, 0);
      $calabel = GUI::HELPERS::create_label(_("CA"), 'left', 1, 0);
      $self->{'nb'}->insert_page($self->{'cabox'}, $calabel, 0);
   } else {
      $self->{'nb'}->hide();
      $self->{'nb'}->remove_page(0);
      $self->{'cabox'}->destroy();
      $self->{'cabox'} = Gtk2::VBox->new(0, 0);
      $calabel = GUI::HELPERS::create_label(_("CA"), 'left', 1, 0);
      $self->{'nb'}->insert_page($self->{'cabox'}, $calabel, 0);
   }

   # frame for CA informations
   $self->{'cainfobox'} = GUI::X509_infobox->new();
   $self->{'cainfobox'}->display($self->{'cabox'}, $parsed, 'cacert',
         _("CA Information"));

   ### notebooktab for certificates

   # delete old instance, force reinitialisation
   if (defined($self->{'certbox'}) && $force) {
      $self->{'certbox'}->destroy();
      delete($self->{'certbox'});
      $self->{'certbox'} = undef;
      delete($self->{'certbrowser'}->{'OpenSSL'});
      $self->{'certbrowser'}->{'OpenSSL'} = undef;
      delete($self->{'certbrowser'});
      $self->{'certbrowser'} = undef;
   }

   if(not defined($self->{'certbox'})) {
      $self->{'certbox'} = Gtk2::VBox->new(0, 0);
      
      $certlabel = GUI::HELPERS::create_label(
            _("Certificates"), 'left', 1, 0);
      $self->{'nb'}->insert_page($self->{'certbox'}, $certlabel, 1);

      if (not defined ($self->{'certbrowser'})) {
        $self->{'certbrowser'}=GUI::X509_browser->new($self, 'cert');
        $self->{'certbrowser'}->set_window($self->{'certbox'});
        $self->{'certbrowser'}->add_list($ca,
                                         $cadir."/certs",
                                         $cadir."/crl/crl.pem",
                                         $cadir."/index.txt");

        $self->{'certbrowser'}->add_info();

        # create popup menu
        if(not defined($self->{'certmenu'})) {
           _create_cert_menu($self);
        }
  
        $self->{'certbrowser'}->{'x509clist'}->signal_connect(
              'button_release_event', 
              sub {  _show_popup_menu($self, 'cert', @_) });
        $self->{'certbrowser'}->{'x509clist'}->signal_connect(
              'button_press_event',
              sub { _show_details_wrapper($self, 'cert', @_)});

        # $self->{'certbrowser'}->destroy();
      } else {
        $self->{'certbrowser'}->update($cadir."/certs",
                                       $cadir."/crl/crl.pem",
                                       $cadir."/index.txt"); 
      }

   } else {
      $self->{'certbrowser'}->update($cadir."/certs",
                                     $cadir."/crl/crl.pem",
                                     $cadir."/index.txt"); 
   }


   ### notebooktab for keys (split info and buttons)
   @keytitles = (_("Common Name"),
                 _("eMail Address"),
                 _("Organizational Unit"),
                 _("Organization"),
                 _("Location"),
                 _("State"),
                 _("Country"),
                 _("Type"));
   # delete old instance, force reinitialisation
   if (defined($self->{'keybox'}) && $force) {
      $self->{'keybox'}->destroy();
      delete($self->{'keybox'});
      $self->{'keybox'} = undef;
      delete($self->{'keybrowser'}->{'OpenSSL'});
      $self->{'keybrowser'}->{'OpenSSL'} = undef;
      delete($self->{'keybrowser'});
      $self->{'keybrowser'} = undef;
   }

   if(not defined($self->{'keybox'})) {
      $self->{'keybox'} = Gtk2::VBox->new(0, 0);
      $keylabel = GUI::HELPERS::create_label( _("Keys"), 'left', 1, 0);
      $self->{'nb'}->insert_page($self->{'keybox'}, $keylabel, 2);

      if (not defined ($self->{'keybrowser'})) {
         $self->{'keybrowser'}=GUI::X509_browser->new($self, 'key');
         $self->{'keybrowser'}->set_window($self->{'keybox'});
         $self->{'keybrowser'}->add_list($ca, 
                                         $cadir."/keys", 
                                         $cadir."/crl/crl.pem", 
                                         $cadir."/index.txt");

         # create popup menu
         if(not defined($self->{'keymenu'})) { 
            _create_key_menu($self);
         }

         $self->{'keybrowser'}->{'x509clist'}->signal_connect(
               'button_release_event', 
               sub {  _show_popup_menu($self, 'key', @_) });

      } else {
         $self->{'keybrowser'}->update($cadir."/keys",
                                       $cadir."/crl/crl.pem",
                                       $cadir."/index.txt");
      }
   
   }

   # delete old instance, force reinitialisation
   if (defined($self->{'reqbox'}) && $force) {
      $self->{'reqbox'}->destroy();
      delete($self->{'reqbox'});
      $self->{'reqbox'} = undef;
      delete($self->{'reqbrowser'}->{'OpenSSL'});
      $self->{'reqbrowser'}->{'OpenSSL'} = undef;
      delete($self->{'reqbrowser'});
      $self->{'reqbrowser'} = undef;
   }

   ### notebooktab for requests (split info and buttons)
   if(not defined($self->{'reqbox'})) {
      $self->{'reqbox'} = Gtk2::VBox->new(0, 0);
      $reqlabel = GUI::HELPERS::create_label(
            _("Requests"), 'left', 1, 0);
      $self->{'nb'}->insert_page($self->{'reqbox'}, $reqlabel, 3);
      
      if (not defined ($self->{'reqbrowser'})) {
        $self->{'reqbrowser'}=GUI::X509_browser->new($self, 'req');
        $self->{'reqbrowser'}->set_window($self->{'reqbox'});
        $self->{'reqbrowser'}->add_list($ca,
                                         $cadir."/req",
                                         $cadir."/crl/crl.pem",
                                         $cadir."/index.txt");

        $self->{'reqbrowser'}->add_info();

        # create popup menu
        if(not defined($self->{'reqmenu'})) {
              _create_req_menu($self);
        }

        $self->{'reqbrowser'}->{'x509clist'}->signal_connect(
              'button_release_event', 
              sub {  _show_popup_menu($self, 'req', @_) });

        $self->{'reqbrowser'}->{'x509clist'}->signal_connect(
              'button_press_event',
              sub { _show_details_wrapper($self, 'req', @_)});

      } else { 
         $self->{'reqbrowser'}->update($cadir."/req",
                                       $cadir."/crl/crl.pem",
                                       $cadir."/index.txt"); 
      }

   } else {
      $self->{'reqbrowser'}->update($cadir."/req",
                                    $cadir."/crl/crl.pem",
                                    $cadir."/index.txt"); 
   }

   $self->{'nb'}->show_all();
   $self->{'nb'}->signal_connect_after('switch-page' => 
         sub { _act_toolbar($self->{'nb'}, $self) });

   $self->{'nb'}->set_current_page(1);

   return;
}

#
# create empty notebook, add to main window and configure
# 
sub create_nb {
   my $self = shift;

   $self->{'nb'} = Gtk2::Notebook->new();
   $self->{'nb'}->set_tab_pos('top');

   return;
}

#
# create the applicationbar
#
sub create_bar {
   my $self = shift;
   
   $self->{'barbox'} = Gtk2::HBox->new();
   $self->{'bar'}    = Gtk2::Statusbar->new();

   $self->{'progress'} = Gtk2::ProgressBar->new();

   $self->{'barbox'}->pack_start($self->{'bar'}, 1, 1, 0);

   GUI::HELPERS::set_status($self, "   Watch out...");
      
   return;
}

#
# keep toolbar in sync with notebook
#
sub _act_toolbar {
   my ($nb, $self) = @_;

   my $page_num = $nb->get_current_page();
   
   my $mode = 'startup';
   my $t;

   if(defined($self->{'CA'}->{'actca'})) {
      if ($page_num == 0) {
         $mode = 'ca';
         $t = _("  Actual CA: %s");
      } elsif ($page_num == 1) {
         $mode = 'cert';
         $t = _("  Actual CA: %s - Certificates");
      } elsif ($page_num == 2) {
         $mode = 'key';
         $t = _("  Actual CA: %s - Keys");
      } elsif ($page_num == 3) {
         $mode = 'req';
         $t = _("  Actual CA: %s - Requests");
      }
   
      if(defined($self->{'CA'}->{'actca'})) {
         $t = sprintf($t, $self->{'CA'}->{'actca'});
         GUI::HELPERS::set_status($self, $t);
      }
   }

   $self->create_toolbar($mode);
}

#
# create the toolbar
#
sub create_toolbar {
   my ($self, $mode) = @_;

   my ($icon, $mask, $iconw, $button, @children, $c, $ca);

   $ca = $self->{'CA'}->{'actca'};

   if(not defined($self->{'separator'})) {
      $self->{'separator'} = Gtk2::SeparatorToolItem->new();
   }
   
   if(defined($self->{'toolbar'})) {
      @children = $self->{'toolbar'}->get_children();

      for(my $i = 6; $i < @children; $i++) {
         $c = $children[$i];
         $c->destroy();
      }
   } else {
      $self->{'toolbar'} = Gtk2::Toolbar->new();
      $self->{'toolbar'}->set_orientation('horizontal');
      $self->{'toolbar'}->set_icon_size('small-toolbar');

      ## Buttons for all toolbars
      $self->{'toolbar'} = Gtk2::Toolbar->new();
      $self->{'toolbar'}->set_orientation('horizontal');

      $button = Gtk2::ToolButton->new_from_stock('gtk-quit');
      $self->{'toolbar'}->insert($button, -1);
      $button->signal_connect('clicked', sub { exit(4) });


      $button = Gtk2::ToolButton->new_from_stock('gtk-open');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Open CA"));
      $button->signal_connect('clicked', sub {
            $self->{'CA'}->get_open_name($self)});

      $button = Gtk2::ToolButton->new_from_stock('gtk-new');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("New CA"));
      $button->signal_connect('clicked', sub {
            $self->{'CA'}->get_ca_create($self)});

      $button = Gtk2::ToolButton->new_from_stock('gtk-convert');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Import CA"));
      $button->signal_connect('clicked', sub {
            $self->{'CA'}->get_ca_import($self)});

      $button = Gtk2::ToolButton->new_from_stock('gtk-delete');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Delete CA"));
      $button->signal_connect('clicked', sub {
            $self->{'CA'}->get_ca_delete($self)});
   
      $self->{'toolbar'}->insert($self->{'separator'}, -1); }

   
   if($mode eq 'ca') {
      $button = Gtk2::ToolButton->new_from_stock('gtk-find');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Details"));
      $button->signal_connect('clicked', sub {
            $self->show_details('CA') });

      $button = Gtk2::ToolButton->new_from_stock('gtk-find-and-replace');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("History"));
      $button->signal_connect('clicked', sub {
            $self->show_history() });
   
      $button = Gtk2::ToolButton->new_from_stock('gtk-new');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Sub CA"));
      $button->signal_connect('clicked', sub {
            $self->{'CA'}->get_ca_create($self, undef, undef, "sub")});
   
      $button = Gtk2::ToolButton->new_from_stock('gtk-save');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Export CA"));
      $button->signal_connect('clicked', sub {
            $self->{'CA'}->export_ca_cert($self)});
   
      $button = Gtk2::ToolButton->new_from_stock('gtk-save');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Export CRL"));
      $button->signal_connect('clicked', sub {
            $self->{'CA'}->export_crl($self)});
      
      if(-s $self->{'CA'}->{$ca}->{'dir'}."/cachain.pem") {
         $button = Gtk2::ToolButton->new_from_stock('gtk-save');
         $self->{'toolbar'}->insert($button, -1);
         $button->set_label(_("Export Chain"));
         $button->signal_connect('clicked', sub {
               $self->{'CA'}->export_ca_chain($self)});
      }

   } elsif($mode eq 'cert') {
      $button = Gtk2::ToolButton->new_from_stock('gtk-find');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Details"));
      $button->signal_connect('clicked', sub {
            $self->show_details('cert') });

      $button = Gtk2::ToolButton->new_from_stock('gtk-find');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("View"));
      $button->signal_connect('clicked', sub {
            $self->show_text('cert') });

      if(not(defined($self->{'newcertmenu'}))) {
         _create_create_cert_menu($self);
      }

      $button = Gtk2::ToolButton->new_from_stock('gtk-new');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("New"));
      $button->signal_connect('clicked' =>
            sub { $self->{'newcertmenu'}->popup( 
               undef, undef, undef, undef, 1, 0) });
      
      $button = Gtk2::ToolButton->new_from_stock('gtk-save');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Export"));
      $button->signal_connect('clicked', sub {
            $self->{'CERT'}->get_export_cert($self) });

      $button = Gtk2::ToolButton->new_from_stock('gtk-stop');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Revoke"));
      $button->signal_connect('clicked', sub {
            $self->{'CERT'}->get_revoke_cert($self) });

      if(not defined($self->{'renewcertmenu'})) {
         _create_renew_cert_menu($self);
      }

      $button = Gtk2::ToolButton->new_from_stock('gtk-refresh');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Renew"));
      $button->signal_connect('clicked' =>
            sub { $self->{'renewcertmenu'}->popup(
               undef, undef, undef, undef, 1, 0) });

      $button = Gtk2::ToolButton->new_from_stock('gtk-delete');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Delete"));
      $button->signal_connect('clicked', sub {
            $self->{'CERT'}->get_del_cert($self) });
      
   } elsif($mode eq 'key') {

      $button = Gtk2::ToolButton->new_from_stock('gtk-save');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Export"));
      $button->signal_connect('clicked', sub {
            $self->{'KEY'}->get_export_key($self) });

      $button = Gtk2::ToolButton->new_from_stock('gtk-delete');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Delete"));
      $button->signal_connect('clicked', sub {
            $self->{'KEY'}->get_del_key($self) });
      
   } elsif($mode eq 'req') {

      $button = Gtk2::ToolButton->new_from_stock('gtk-find');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Details"));
      $button->signal_connect('clicked', sub {
            $self->show_details('req') });

      $button = Gtk2::ToolButton->new_from_stock('gtk-find');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("View"));
      $button->signal_connect('clicked', sub {
            $self->show_text('req') });
      
      $button = Gtk2::ToolButton->new_from_stock('gtk-new');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("New"));
      $button->signal_connect('clicked', sub {
            $self->{'REQ'}->get_req_create($self) });
      
      $button = Gtk2::ToolButton->new_from_stock('gtk-revert-to-saved');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Import"));
      $button->signal_connect('clicked', sub {
            $self->{'REQ'}->get_import_req($self) });

      if(not(defined($self->{'reqsignmenu'}))) {
         _create_sign_req_menu($self);
      }

      $button = Gtk2::ToolButton->new_from_stock('gtk-properties');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Sign"));
      $button->signal_connect('clicked' =>
            sub { $self->{'reqsignmenu'}->popup(
               undef, undef, undef, undef, 1, 0) });

      $button = Gtk2::ToolButton->new_from_stock('gtk-delete');
      $self->{'toolbar'}->insert($button, -1);
      $button->set_label(_("Delete"));
      $button->signal_connect('clicked', sub {
            $self->{'REQ'}->get_del_req($self) });
   }

   $self->{'toolbar'}->set_icon_size('small-toolbar');

   $self->{'toolbar'}->show_all();

   return;
}

#
# create the menubar
#
sub create_menu {
   my $self = shift;

   my $menu_tree = [
      _("_CA") => {
         item_type => '<Branch>',
         children => [
            _("_Open CA") => {
               callback   => sub { $self->{'CA'}->get_open_name($self) },
               item_type  => '<StockItem>',
               extra_data => 'gtk-open'
            },
            _("_New CA") => {
               callback    => sub { $self->{'CA'}->get_ca_create($self)},
               item_type   => '<StockItem>',
               extra_data => 'gtk-new'
            },
            _("_Delete CA") => {
               callback    => sub { $self->{'CA'}->get_ca_delete($self)},
               item_type   => '<StockItem>',
               extra_data  => 'gtk-delete'
            },
            Separator => {
               item_type => '<Separator>',
            },
            _("_Exit") => {
               callback    => sub { exit(3) },
               item_type   => '<StockItem>',
               extra_data  => 'gtk-close'
            }
         ],
      },
      _("_Preferences") => {
         item_type => '<Branch>',
         children => [
            _("Experts Only!!") => {
            },
            Separator => {
               item_type => '<Separator>',
            },
            _("OpenSSL _Configuration") => {
               callback    => sub{ $self->{'TCONFIG'}->config_openssl($self) },
               item_type   => '<StockItem>',
               extra_data => 'gtk-preferences'
            }
         ],
      },
      _("_Help") => {
         item_type => '<Branch>',
         children => [
            _("_Help") => {
               callback    => sub{ $self->show_help() },
               item_type   => '<StockItem>',
               extra_data => 'gtk-help'
            },
            _("_About TinyCA") => {
               callback    => sub { $self->about($self) },
               item_type   => '<StockItem>',
               extra_data => 'gtk-about'
            }
         ],
      }
   ];

   $self->{'menu'} = Gtk2::SimpleMenu->new(menu_tree => $menu_tree);

   return;
}

#
# pop-up to display request/cert as TXT
#
sub show_text {
   my ($self, $mode) = @_;

   my($parsed, $t, $box, $label, $text, $vscrollbar, $name, $button_ok,
         $status, $scrolled, $ca, $buffer);

   $ca = $self->{'CA'}->{'actca'};

   if($mode eq 'req') {
      $name = $self->{'reqbrowser'}->selection_dn();
   } elsif($mode eq 'cert') {
      $name = $self->{'certbrowser'}->selection_dn();
   } else {
      GUI::HELPERS::print_error(
            _("Invalid mode for show_text():")." ".$mode);
      return;
   }

   if((not defined $name) && ($mode eq 'req')) { 
      GUI::HELPERS::print_info(_("Please select a Request first"));
      return;
   }elsif((not defined $name) && ($mode eq 'cert')) {
      GUI::HELPERS::print_info(_("Please select a certificate first"));
      return;
   }

   if($mode eq 'cert') {
      $status = $self->{'certbrowser'}->selection_status();
   }

   $name = HELPERS::enc_base64($name);

   if($mode eq 'req') {
      $parsed = $self->{'REQ'}->parse_req( $self, $name);
   } elsif($mode eq 'cert') {
      $parsed = $self->{'CERT'}->parse_cert( $self, $name);
   }

   defined($parsed) || GUI::HELPERS::print_error(_("Can't read file"));

   $t = $mode eq 'req'?_("Request"):_("Certificate");
   
   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', sub { $box->destroy() });
   $button_ok->can_default(1);

   $box = GUI::HELPERS::dialog_box($t, $t, $button_ok);

   $box->set_default_size(550, 440);
   $button_ok->grab_default();

   $scrolled = Gtk2::ScrolledWindow->new(undef, undef);
   $scrolled->set_policy('automatic', 'automatic');
   $scrolled->set_shadow_type('etched-in');
   $box->vbox->pack_start($scrolled, 1, 1, 0);

   $buffer = Gtk2::TextBuffer->new();
   $buffer->set_text($parsed->{'TEXT'});

   $text = Gtk2::TextView->new_with_buffer($buffer);
   $text->set_editable(0);
   $text->set_wrap_mode('none');

   $text->modify_font($self->{'fontfix'});

   $scrolled->add($text);

   $box->show_all();
   return;
}

#
# completeley sick, but needed for doubleclick
#
sub _show_details_wrapper {
   my ($self, $mode, $list, $event) = @_;

   return(0) if($event->type() ne '2button-press');

   show_details($self, $mode);

   return(1);
}

#
# called on rightclick in [key|cert|reqlist]
#
sub _show_popup_menu {
   my ($self, $mode, $list, $event) = @_;

   my $t;

   if ($event->button() == 3) {
      if($mode eq 'cert') {
         $self->{'certmenu'}->popup(undef, undef, undef, undef, 3, 0);
      } elsif ($mode eq 'req') {
         $self->{'reqmenu'}->popup(undef, undef, undef, undef, 3, 0);
      } elsif ($mode eq 'key') {
         $self->{'keymenu'}->popup(undef, undef, undef, undef, 3, 0);
      } else { 
         $t = sprintf(
               _("Invalid mode for _show_popup_menu(): %s"), $mode);
         GUI::HELPERS::print_error($t);
      }
      return(1); 
   }

   return(0);
}

#
# show request/certificate informations and extensions
#
sub show_details {
   my ($self, $mode) = @_;

   my($name, $status, $parsed, $row, $ind, $label, $table, $tree, $box,
         $button_ok, $t, @fields, $ca);

   $ca   = $self->{'CA'}->{'actca'};

   if($mode eq 'req') {
      $name = $self->{'reqbrowser'}->selection_dn();
   } elsif($mode eq 'cert') {
      $name = $self->{'certbrowser'}->selection_dn();
   } elsif($mode eq 'CA') {
      $name = 'CA';
   } else {
      GUI::HELPERS::print_error(
            _("Invalid mode for show_details():")." ".$mode);
      return;
   }

   if((not defined $name) && ($mode eq 'req')) { 
      GUI::HELPERS::print_info(_("Please select a Request first"));
      return;
   }elsif((not defined $name) && ($mode eq 'cert')) {
      GUI::HELPERS::print_info(_("Please select a Certificate first"));
      return;
   }

   if($mode eq 'cert') {
      $status = $self->{'certbrowser'}->selection_status();
   }

   $name = HELPERS::enc_base64($name) if($name ne 'CA');

   if($mode eq 'req') {
      $parsed = $self->{'REQ'}->parse_req( $self, $name);
   } elsif($mode eq 'cert' || $mode eq 'CA') {
      $parsed = $self->{'CERT'}->parse_cert( $self, $name);
   }

   defined($parsed) || GUI::HELPERS::print_error(_("Can't read file"));

   $t = $mode eq 'req'?_("Request Details"):_("Certificate Details");
   
   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);
   $button_ok->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box($t, $t, $button_ok);
   $box->set_default_size(700, 400);

   $button_ok->grab_default();

   $mode = 'cert' if($mode eq 'CA');
   
   $tree = $self->create_detail_tree($parsed, $mode);
   $box->vbox->add($tree);

   $box->show_all();
   $tree->{'tree'}->columns_autosize();
}

#
# pop-up to verify import
#
sub show_import_verification {
   my ($self, $mode, $opts, $parsed) = @_;

   my($box, $button_ok, $button_cancel, $label, $rows, $tree, $t);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);
   if($mode eq "req") {
      $button_ok->signal_connect('clicked', 
         sub { $self->{'REQ'}->import_req($self, $opts, $parsed, $box) });
   } elsif($mode eq "cacert") {
      $button_ok->signal_connect('clicked', 
         sub { $self->{'CA'}->import_ca($self, $opts, $box) });
   }

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   if($mode eq "req") {
      $t = _("Import Request");
   } elsif($mode eq "cacert") {
      $t = _("Import CA Certificate");
   }
   $box = GUI::HELPERS::dialog_box( $t, $t, $button_ok, $button_cancel);
   $box->set_default_size(700, 400);

   $button_ok->grab_default();

   if($mode eq "req") {
      $t = _("Do you want to import the following Certificate Request?");
   } elsif($mode eq "cacert") {
      $t = _("Do you want to import the following CA Certificate?");
   }
   $label = GUI::HELPERS::create_label($t, 'center', 1, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $tree = $self->create_detail_tree($parsed, $mode);
   $box->vbox->pack_start($tree, 1, 1, 0);

   $box->show_all();

   return;
}

#
# create tree with details (cert/req)
#
sub create_detail_tree {
   my ($self, $parsed, $mode) = @_;

   # print STDERR "DEBUG: create_detail_tree called with mode $mode\n";

   my ($tree, $tree_scrolled, $t, $root, $store, $piter, $citer, $column,
         $ind, $nsext);

   $tree_scrolled = Gtk2::ScrolledWindow->new(undef, undef);
   $tree_scrolled->set_policy('automatic', 'automatic');
   $tree_scrolled->set_shadow_type('etched-in');

   $store = Gtk2::TreeStore->new('Glib::String','Glib::String');
   $tree  = Gtk2::TreeView->new_with_model($store);
   $tree->get_selection->set_mode('none');
   $tree->set_headers_visible(0);

   $tree_scrolled->{'tree'} = $tree;

   my @titles = ("", "");
   $ind = 0;
   foreach my $title (@titles) {
      $column   = Gtk2::TreeViewColumn->new_with_attributes(
            $title, Gtk2::CellRendererText->new(), 'text' => $ind);
      $tree->append_column($column);
      $ind++;
   }

   $tree_scrolled->add_with_viewport($tree);

   $t = $mode eq 'req'?_("Request Details"):_("Certificate Details"); 
   $t .= " - $parsed->{'CN'}";
   
   $root = $store->append(undef);
   $store->set($root, 0 => $t);

   # Information about Subject DN

   $t = _("Subject DN").":";
   $piter = $store->append($root);
   $store->set($piter, 0 => $t);

   for my $l qw(CN EMAIL O OU C ST L) {
      if(defined($parsed->{$l})) {
         if($l eq "OU") {
            foreach my $ou (@{$parsed->{'OU'}}) {
               $citer = $store->append($piter);
               $store->set($citer, 
                     0 => $self->{'words'}{$l}, 
                     1 => $ou);
            }
         } else {
            $citer = $store->append($piter);
            $store->set($citer, 
                  0 => $self->{'words'}{$l}, 
                  1 => $parsed->{$l});
         }
      }
   }

   if($mode ne "req") {
      # Information about Issuer
      $t = _("Issuer").":";

      $piter = $store->append($root);
      $store->set($piter, 0 => $t);
   
      for my $l qw(CN EMAIL O OU C ST L) {
         if(defined($parsed->{'ISSUERDN'}->{$l})) {
            if($l eq "OU") {
               foreach my $ou (@{$parsed->{'ISSUERDN'}->{'OU'}}) {
                  $citer = $store->append($piter);
                  $store->set($citer, 
                        0 => $self->{'words'}{$l}, 
                        1 => $ou);
               }
            } else {
               $citer = $store->append($piter);
               $store->set($citer, 
                     0 => $self->{'words'}{$l}, 
                     1 => $parsed->{'ISSUERDN'}->{$l});
            }
         }
      }
   }

   if($mode ne "req") {
      # Information about Validity
      $t = _("Validity").":";

      $piter = $store->append($root);
      $store->set($piter, 0 => $t);
   
      for my $l qw(STATUS NOTBEFORE NOTAFTER) {
         if(defined($parsed->{$l})) {
            $citer = $store->append($piter);
            $store->set($citer, 
                  0 => $self->{'words'}{$l}, 
                  1 => $parsed->{$l});
         }
      }
   }

   # Information about Key/Certificate
   $t = $mode eq 'req'?_("Key/Request Details:"):_("Key/Certificate Details:"); 
   $piter = $store->append($root);
   $store->set($piter, 0 => $t);


   for my $l qw(STATUS SERIAL KEYSIZE PK_ALGORITHM SIG_ALGORITHM TYPE) {
      if(defined($parsed->{$l})) {
         $citer = $store->append($piter);
         $store->set($citer, 
               0 => $self->{'words'}{$l}, 
               1 => $parsed->{$l});
      }
   }

   if($mode ne "req") {
      # Fingerprints
      $t = _("Fingerprints").":";
      $piter = $store->append($root);
      $store->set($piter, 0 => $t);
   
      for my $l qw(FINGERPRINTMD5 FINGERPRINTSHA1) {
         if(defined($parsed->{$l})) {
            $citer = $store->append($piter);
            $store->set($citer, 
                  0 => $self->{'words'}{$l}, 
                  1 => $parsed->{$l});
         }
      }
   }

   # Information about Key/Certificate
   if(keys(%{$parsed->{'EXT'}})) {
      $t = $mode eq 'req'?_("Requested X.509 Extensions"):_("X.509v3 Extensions");
      $piter = $store->append($root);
      $store->set($piter, 0 => $t);
   
      while(my ($key, $val) = each(%{$parsed->{'EXT'}})) { 
         if($key =~ /^netscape/i) {
            $nsext = 1; next;
         }
         # print STDERR "DEBUG: print key: >$key< val: >$val->[0]<\n";
         $citer = $store->append($piter);
         $store->set($citer,
               0 => $key,
               1 => $val->[0]);

         if(@{$val} > 1) {
            for(my $i = 1; $val->[$i]; $i++) { 
               $citer = $store->append($piter);
               $store->set($citer,
                     0 => $key,
                     1 => $val->[$i]);
            }
         }
      }

      if($nsext) {
         $t = $mode eq 'req'?_("Requested Netscape Extensions"):_("Netscape Extensions");
         $piter = $store->append($root);
         $store->set($piter, 0 => $t);
      
         while(my ($key, $val) = each(%{$parsed->{'EXT'}})) { 
            if($key !~ /^netscape/i) {
               next;
            }
            $citer = $store->append($piter);
            $store->set($citer,
                  0 => $key,
                  1 => $val->[0]);
   
            if(@{$val} > 1) {
               for(my $i = 1; $val->[$i]; $i++) { 
                  $t = [$key, $val->[$i]];
                  $citer = $store->append($piter);
                  $store->set($citer,
                        0 => $key,
                        1 => $val->[$i]);
               }
            }
         }
      }
   }
   $tree->expand_to_path(Gtk2::TreePath->new_first());

   return($tree_scrolled);
}


#
# get name for open/delete a CA
#
sub show_select_ca_dialog {
   my ($self, $action, $opts)= @_;

   my ($box, $button_ok, $button_cancel, $label, $scrolled, $list, 
         $model, $name, $t, $store, $column, $iter);

   if($action eq 'open') {
      $t = _("Open CA");
   }elsif($action eq 'delete') {
      $t = _("Delete CA");
   }else {
      GUI::HELPERS::print_error(_("Invalid action given: ").$action);
      return;
   }
   
   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $button_ok->signal_connect('clicked', 
         sub { 
            $iter = $list->get_selection->get_selected();
            if(defined($iter)) {
               $name = $store->get($iter);
               if($action eq 'open') {
                  $opts->{'name'} = $name;
                  $self->{'CA'}->open_ca($self, $opts, $box);
               }elsif($action eq 'delete') {
                  $self->{'CA'}->delete_ca($self, $name, $box);
               }else {
                  GUI::HELPERS::print_error(
                     _("Invalid action for show_select_ca_dialog(): ").$action);
               }
            }
         }
   );

   $box = GUI::HELPERS::dialog_box($t, $t, $button_ok, $button_cancel);

   $button_ok->grab_default();

   $scrolled = Gtk2::ScrolledWindow->new(undef, undef);
   $scrolled->set_policy('automatic', 'automatic' );
   $scrolled->set_shadow_type('etched-in');
   $box->vbox->add($scrolled);

   $store = Gtk2::ListStore->new('Glib::String');

   $list = Gtk2::TreeView->new_with_model ($store);
   $list->get_selection->set_mode('single');
   $scrolled->add_with_viewport($list);

   $column   = Gtk2::TreeViewColumn->new_with_attributes(
         _("Available CAs"), Gtk2::CellRendererText->new(), 'text' => 0);
   $list->append_column($column);

   foreach(@{$self->{'CA'}->{'calist'}}) {
      next if (not defined $_ );
      $iter = $store->append();
      $store->set($iter, 0, $_);
   }

   # activate doubleclick in the list
   $list->signal_connect('button_press_event', 
         sub { 
            if($_[1]->type() eq '2button-press') {
               $iter = $list->get_selection->get_selected();
               if($iter) {
                  $name = $store->get($iter);

                  if($action eq 'open') {
                     $opts->{'name'} = $name;
                     $self->{'CA'}->open_ca($self, $opts, $box);
                  }elsif($action eq 'delete') {
                     $self->{'CA'}->delete_ca($self, $name, $box);
                  }else {
                     GUI::HELPERS::print_error(
                        _("Invalid action for show_select_ca_dialog(): ").$action);
                  }
               }
               return(1);
            }
            return(0);
         }
   );

   $button_ok->grab_default();

   $box->show_all();
}

#
# get data for creating a new request
#
sub show_req_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $reqtable, $radiobox, $key1, $key2,
         $key3, $key4, $key5, $entry, $label);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);
   $button_ok->signal_connect('clicked', 
      sub { $self->{'REQ'}->get_req_create($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Create Request"), 
         _("Create a new Certificate Request"),
         $button_ok, $button_cancel);

   # table for request data
   my $cc=0;
   my $ous = 1;
   if(defined($opts->{'OU'})) {
      $ous = @{$opts->{'OU'}} - 1;
   }
   $reqtable = Gtk2::Table->new(1, 13 + $ous, 0);
   $reqtable->set_col_spacing(0, 7);
   $box->vbox->add($reqtable);

   $entry = GUI::HELPERS::entry_to_table(
         _("Common Name (eg, your Name,"),
         \$opts->{'CN'}, $reqtable, 0, 1);
   $entry->grab_focus();

   $label = GUI::HELPERS::create_label(
         _("your eMail Address"), 'right', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 2, 3);

   $label = GUI::HELPERS::create_label(
         _("or the Servers Name)"), 'right', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 3, 4);

   $entry = GUI::HELPERS::entry_to_table(
         _("eMail Address").":",
         \$opts->{'EMAIL'}, $reqtable, 4, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Password (protect your private Key):"),
         \$opts->{'passwd'}, $reqtable, 5, 0);

   $entry = GUI::HELPERS::entry_to_table(
         _("Password (confirmation):"),
         \$opts->{'passwd2'}, $reqtable, 6, 0);

   $entry = GUI::HELPERS::entry_to_table(
         _("Country Name (2 letter code):"),
         \$opts->{'C'}, $reqtable, 7, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("State or Province Name:"),
         \$opts->{'ST'}, $reqtable, 8, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Locality Name (eg. city):"),
         \$opts->{'L'}, $reqtable, 9, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Organization Name (eg. company):"),
         \$opts->{'O'}, $reqtable, 10, 1);

   if(defined($opts->{'OU'})) {
      foreach my $ou (@{$opts->{'OU'}}) {
         $entry = GUI::HELPERS::entry_to_table(
               _("Organizational Unit Name (eg. section):"),
            \$ou, $reqtable, 11 + $cc++, 1);
      }
   } else {
      $entry = GUI::HELPERS::entry_to_table(
            _("Organizational Unit Name (eg. section):"),
            \$opts->{'OU'}, $reqtable, 11, 1);
   }

   $label = GUI::HELPERS::create_label(
         _("Keylength").":", 'left', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 13, 14);

   $radiobox = Gtk2::HBox->new(0, 0);
   _fill_radiobox($radiobox, \$opts->{'bits'}, %bit_lengths);
   $reqtable->attach_defaults($radiobox, 1, 2, 13, 14);

   $label = GUI::HELPERS::create_label(
         _("Digest").":", 'left', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 15, 16);

   $radiobox = Gtk2::HBox->new(0, 0);
   _fill_radiobox($radiobox, \$opts->{'digest'}, %md_algorithms);
   $reqtable->attach_defaults($radiobox, 1, 2, 15, 16);

   $label = GUI::HELPERS::create_label(_("Algorithm").":", 'left', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 16, 17);

   $radiobox = Gtk2::HBox->new(0, 0);
   _fill_radiobox($radiobox, \$opts->{'algo'},
		   'rsa' => 'RSA',
		   'dsa' => 'DSA');
   $reqtable->attach_defaults($radiobox, 1, 2, 16, 17);

   $box->show_all();

   return;
}

#
# get data for revoking a certificate
#
sub show_cert_revoke_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $table, $entry, $t, $label, $combo,
         @combostrings);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', 
      sub { $self->{'CERT'}->get_revoke_cert($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Revoke Certificate"), _("Revoke Certificate"),
         $button_ok, $button_cancel);

   # small table for data
   $table = Gtk2::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = GUI::HELPERS::entry_to_table(
         _("CA Password:"), \$opts->{'passwd'}, $table, 0, 0);
   $entry->grab_focus();

   if($self->{'OpenSSL'}->{'version'} !~ /^0\.9\.[0-6][a-z]?$/) {
      # OpenSSL < 0.9.7 was not able to handle revocation reasons
      $label = GUI::HELPERS::create_label(
            _("Revocation Reason:"), 'left', 0, 0);
   
      $table->attach_defaults($label, 0, 1, 1, 2);
   
      $combo = Gtk2::Combo->new();
      @combostrings = qw(
            unspecified 
            keyCompromise 
            CACompromise 
            affiliationChanged 
            superseded 
            cessationOfOperation 
            certificateHold);
      $combo->set_popdown_strings(@combostrings);
      $combo->set_use_arrows(1);
      $combo->set_value_in_list(1, 0);
   
      $combo->entry->signal_connect('changed' =>
            sub{GUI::CALLBACK::entry_to_var(
               $combo, $combo->entry, \$opts->{'reason'}, undef, undef)});
   
      $table->attach_defaults($combo, 1, 2, 1, 2); }

   $box->show_all();
         
   return;
}

#
# get data for exporting a crl
#
sub show_crl_export_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $button, $label, $format1, $format2,
         $format3, $table, $entry, $fileentry, $hbox);

   $button_ok = Gtk2::Button->new_from_stock('gtk-save');
   $button_ok->signal_connect('clicked' =>
         sub { $self->{'CA'}->export_crl($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Export CRL"), _("Export Revocation List to File"),
         $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk2::Table->new(3, 3, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = GUI::HELPERS::create_label(_("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $fileentry = Gtk2::Entry->new();
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->set_text($opts->{'outfile'}) if(defined($opts->{'outfile'}));
   $fileentry->signal_connect( 'changed' => 
         sub{GUI::CALLBACK::entry_to_var(
            $fileentry, $fileentry, \$opts->{'outfile'})});
   $fileentry->grab_focus();

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' =>
      sub{GUI::HELPERS::browse_file(
         _("Export CA Certificate"), $fileentry, 'save')});
   $table->attach_defaults($button, 2, 3, 0, 1);

   $entry = GUI::HELPERS::entry_to_table(_("CA Password:"),
         \$opts->{'passwd'}, $table, 1, 0);
   $entry->grab_focus();

   $entry = GUI::HELPERS::entry_to_table(_("Valid for (Days):"),
         \$opts->{'days'}, $table, 2, 1);

   $label = GUI::HELPERS::create_label(
      _("Export Format:"), 'left', 0, 0);
   $box->vbox->add($label);

   $hbox = Gtk2::HBox->new(0, 0);
   $box->vbox->add($hbox);

   $format1 = Gtk2::RadioButton->new(undef, _("PEM"));
   $format1->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'PEM');
   $format1->signal_connect('toggled' =>
     sub{GUI::CALLBACK::toggle_to_var($format1,
         \$opts->{'format'}, 'PEM', \$opts->{'outfile'}, 
         \$opts->{'format'}, $fileentry)});
   $hbox->add($format1);

   $format2 = Gtk2::RadioButton->new($format1, _("DER"));
   $format2->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'DER');
   $format2->signal_connect('toggled' =>
     sub{GUI::CALLBACK::toggle_to_var($format2,
         \$opts->{'format'}, 'DER', \$opts->{'outfile'}, 
         \$opts->{'format'}, $fileentry)});
   $hbox->add($format2);

   $format3 = Gtk2::RadioButton->new($format1, _("TXT"));
   $format3->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'TXT');
   $format3->signal_connect('toggled' =>
        sub{ GUI::CALLBACK::toggle_to_var($format3,
         \$opts->{'format'}, 'TXT', \$opts->{'outfile'}, 
         \$opts->{'format'}, $fileentry)});
   $hbox->add($format3);

   $box->show_all();

   return;
}

#
# get data for exporting a ca certificate chain
#
sub show_ca_chain_export_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $button, $label, $format1, $format2,
         $format3, $table, $fileentry, $hbox);

   $button_ok     = Gtk2::Button->new_from_stock('gtk-save');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'CA'}->export_ca_chain($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Export CA Certificate Chain"), 
         _("Export CA Certificate Chain to File"),
         $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk2::Table->new(1, 3, 0);
   $box->vbox->add($table);

   $label = GUI::HELPERS::create_label(_("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $fileentry = Gtk2::Entry->new();
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->set_text($opts->{'outfile'}) if(defined($opts->{'outfile'}));
   $fileentry->signal_connect( 'changed' =>
        sub { GUI::CALLBACK::entry_to_var(
           $fileentry, $fileentry, \$opts->{'outfile'}) });
   $fileentry->grab_focus();

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' =>
      sub{GUI::HELPERS::browse_file(
         _("Export CA Certificate Chain"), $fileentry, 'save')});
   $table->attach_defaults($button, 2, 3, 0, 1);

   $box->show_all();

   return;
}

#
# get data for exporting a ca certificate
#
sub show_ca_export_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $label, $format1, $format2,
         $format3, $table, $entry, $fileentry, $hbox, $button);

   $button_ok = Gtk2::Button->new_from_stock('gtk-save');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'CA'}->export_ca_cert($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Export CA Certificate"), 
         _("Export CA Certificate to File"),
         $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk2::Table->new(1, 3, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = GUI::HELPERS::create_label(_("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $fileentry = Gtk2::Entry->new();
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->set_text($opts->{'outfile'}) if(defined($opts->{'outfile'}));
   $fileentry->signal_connect('changed' =>
        sub{GUI::CALLBACK::entry_to_var(
           $fileentry, $fileentry, \$opts->{'outfile'})});
   $fileentry->grab_focus();

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' => 
         sub{GUI::HELPERS::browse_file(
            _("Export CA Certificate"), $fileentry, 'save')});
   $table->attach_defaults($button, 2, 3, 0, 1);

   $label = GUI::HELPERS::create_label(
         _("Export Format:"), 'left', 0, 0);
   $box->vbox->add($label);

   $hbox = Gtk2::HBox->new(0, 0);
   $box->vbox->add($hbox);

   $format1 = Gtk2::RadioButton->new(undef, _("PEM"));
   $format1->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'PEM');
   $format1->signal_connect_after('toggled' =>
        sub{GUI::CALLBACK::toggle_to_var($format1, 
           \$opts->{'format'}, 'PEM', \$opts->{'outfile'}, 
           \$opts->{'format'}, $fileentry)});
   $hbox->add($format1);

   $format2 = Gtk2::RadioButton->new($format1, _("DER"));
   $format2->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'DER');
   $format2->signal_connect_after('toggled' =>
        sub{GUI::CALLBACK::toggle_to_var($format2,
         \$opts->{'format'}, 'DER', \$opts->{'outfile'}, 
         \$opts->{'format'}, $fileentry)});
   $hbox->add($format2);

   $format3 = Gtk2::RadioButton->new($format1, _("TXT"));
   $format3->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'TXT');
   $format3->signal_connect_after('toggled' => 
      sub{GUI::CALLBACK::toggle_to_var($format3,
         \$opts->{'format'}, 'TXT', \$opts->{'outfile'}, 
         \$opts->{'format'}, $fileentry)});
   $hbox->add($format3);

   $box->show_all();

   return;
}

#
# get password for exporting keys
#
sub show_key_nopasswd_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $label, $table, $entry);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'KEY'}->get_export_key($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Export Key without Passphrase"), 
         _("Export Key without Passphrase"),
         $button_ok, $button_cancel);

   $label = GUI::HELPERS::create_label(
         _("I hope you know what you\'re doing?"), 'center', 1, 0);
   $box->vbox->add($label);

   $label = GUI::HELPERS::create_label(
         _("The Key Passphrase is needed for decryption of the Key"),
         'center', 1, 0);
   $box->vbox->add($label);

   # small table for data
   $table = Gtk2::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = GUI::HELPERS::entry_to_table(_("Password:"),
         \$opts->{'passwd'}, $table, 0, 0);
   $entry->grab_focus();

   $box->show_all();
         
   return;
}

#
# get filename for importing a request
#
sub show_req_import_dialog {
   my $self = shift;

   my $opts = {};
   my($box, $button_ok, $button_cancel, $button, $entry, $table, $label);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'REQ'}->get_import_req($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Import Request"), _("Import Request from File"),
         $button_ok, $button_cancel);

   # small table for data
   $table = Gtk2::Table->new(2, 3, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = GUI::HELPERS::create_label(_("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $entry = Gtk2::Entry->new();
   $table->attach_defaults($entry, 1, 2, 0, 1);
   $entry->signal_connect( 'changed' =>
        sub{ GUI::CALLBACK::entry_to_var($entry,
         $entry, \$opts->{'infile'})});
   $entry->grab_focus();

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' =>
         sub{GUI::HELPERS::browse_file(
            _("Import Request from File"), $entry, 'open')});
   $table->attach_defaults($button, 2, 3, 0, 1);

   $box->show_all();

   return;
}


#
# get data for exporting a certificate
#
sub show_export_dialog {
   my ($self, $opts, $mode) = @_;

   my ($box, $button_ok, $button_cancel, $button, $label, $table, $entry,
         $fileentry, $format1, $format2, $format3, $format4, $format5,
         $format6, $passbox, $pass1, $pass2, $title, $text, $t, $incbox,
         $inc1, $inc2, $fpbox, $incfp1, $incfp2);

   if($mode eq 'cert') {
      $title = _("Export Certificate");
   } elsif($mode eq 'key') {
      $title = _("Export Key");
   } else {
      GUI::HELPERS::print_error(
            _("Invalid mode for show_export_dialog(): ").$mode);
      return;
   }
         
   $button_ok     = Gtk2::Button->new_from_stock('gtk-save');
   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');

   if($mode eq 'cert') {
      $button_ok->signal_connect('clicked', 
            sub { $self->{'CERT'}->get_export_cert($self, $opts, $box) });
   } else {
      $button_ok->signal_connect('clicked',
            sub { $self->{'KEY'}->get_export_key($self, $opts, $box) });
   }
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   if($mode eq 'cert') {
      $text = _("Export Certificate to File");
   } else {
      $text = _("Export Key to File");
   }
   
   $box = GUI::HELPERS::dialog_box($title, $text, $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk2::Table->new(1, 3, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = GUI::HELPERS::create_label(_("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   if($mode eq 'cert') {
      $t = _("Export Certificate");
   }else {
      $t = _("Export Key");
   }
   
   $fileentry = Gtk2::Entry->new();
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->set_text($opts->{'outfile'}) if(defined($opts->{'outfile'}));
   $fileentry->signal_connect( 'changed', 
         sub{ GUI::CALLBACK::entry_to_var(
            $fileentry, $fileentry, \$opts->{'outfile'})});
   $fileentry->grab_focus();

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' => 
         sub{GUI::HELPERS::browse_file(
            $t, $fileentry, 'save')});
   $table->attach_defaults($button, 2, 3, 0, 1);

   $label = GUI::HELPERS::create_label(
      _("Export Format:"), 'center', 0, 0);
   $box->vbox->add($label);
   
   if($mode eq 'cert') {
      $t = _("PEM (Certificate)");
   }else {
      $t = _("PEM (Key)");
   }
   
   $format1 = Gtk2::RadioButton->new(undef, $t);
   $format1->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'PEM');
   $box->vbox->add($format1);

   if($mode eq 'cert') {
      $t = _("DER (Certificate)");
   }else {
      $t = _("DER (Key without Passphrase)");
   }

   $format2 = Gtk2::RadioButton->new($format1, $t);
   $format2->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'DER');
   $box->vbox->add($format2);

   $t = _("PKCS#12 (Certificate & Key)");

   $format3 = Gtk2::RadioButton->new($format1, $t);
   $format3->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'P12');
   $box->vbox->add($format3);

   $t = _("Zip (Certificate & Key)");

   $format4 = Gtk2::RadioButton->new($format1, $t);
   $format4->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'ZIP');
   $box->vbox->add($format4);
   if(not -x $self->{'init'}->{'zipbin'}) {
      $format4->set_sensitive(0);
   }

   $t = _("Tar (Certificate & Key)");

   $format5 = Gtk2::RadioButton->new($format1, $t);
   $format5->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'TAR');
   $box->vbox->add($format5);
   if(not -x $self->{'init'}->{'tarbin'}) {
      $format5->set_sensitive(0);
   }

   if($mode eq 'cert') {
      $format6 = Gtk2::RadioButton->new(
            $format1, _("TXT (Certificate)"));
      $format6->set_active(1)
         if(defined($opts->{'format'}) && $opts->{'format'} eq 'TXT');
      $box->vbox->add($format6);
   } else { # no password for PEM key
      $label = GUI::HELPERS::create_label(
            _("Without Passphrase (PEM/PKCS#12)"), 'left', 0, 0);
      $box->vbox->add($label);

      $passbox = Gtk2::HBox->new(0, 0);
      $box->vbox->add($passbox);

      $pass1 = Gtk2::RadioButton->new(undef, _("Yes"));
      $pass1->set_active(1)
         if(defined($opts->{'nopass'}) && $opts->{'nopass'} == 1);
      $passbox->add($pass1);

      $pass2 = Gtk2::RadioButton->new($pass1, _("No"));
      $pass2->set_active(1)
         if(defined($opts->{'nopass'}) && $opts->{'nopass'} == 0);
      $passbox->add($pass2);
   }
   
   # add key/certificate

   if($mode eq 'cert') {
      $label = GUI::HELPERS::create_label(
            _("Include Key (PEM)"), 'left', 0, 0);
      $box->vbox->add($label);

   } else {
      $label = GUI::HELPERS::create_label(
            _("Include Certificate (PEM)"), 'left', 0, 0);
      $box->vbox->add($label);
   }

   $incbox = Gtk2::HBox->new(0, 0);
   $box->vbox->add($incbox);

   $inc1 = Gtk2::RadioButton->new(undef, _("Yes"));
   $inc1->set_active(1)
      if(defined($opts->{'include'}) && $opts->{'include'} == 1);
   $incbox->add($inc1);

   $inc2 = Gtk2::RadioButton->new($inc1, _("No"));
   $inc2->set_active(1)
      if(defined($opts->{'include'}) && $opts->{'include'} == 0);
   $incbox->add($inc2);
   
   # add fingerprint
   if($mode eq 'cert') {
      $label = GUI::HELPERS::create_label(
            _("Include Fingerprint (PEM)"), 'left', 0, 0);
      $box->vbox->add($label);

      $fpbox = Gtk2::HBox->new(0, 0);
      $box->vbox->add($fpbox);

      $incfp1 = Gtk2::RadioButton->new(undef, _("Yes"));
      $incfp1->set_active(1)
         if(defined($opts->{'incfp'}) && $opts->{'incfp'} == 1);
      $fpbox->add($incfp1);

      $incfp2 = Gtk2::RadioButton->new($incfp1, _("No"));
      $incfp2->set_active(1)
         if(defined($opts->{'incfp'}) && $opts->{'incfp'} == 0);
      $fpbox->add($incfp2);
   }

   if($mode eq 'cert') {
      $format1->signal_connect('toggled' =>
        sub{ GUI::CALLBACK::toggle_to_var($format1,
            \$opts->{'format'}, 'PEM', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry)});
      $format2->signal_connect('toggled' =>
           sub{ &GUI::CALLBACK::toggle_to_var($format2,
            \$opts->{'format'}, 'DER', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry)});
      $format3->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format3,
            \$opts->{'format'}, 'P12', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry)});
      $format4->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format4,
            \$opts->{'format'}, 'ZIP', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry)});
      $format5->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format5,
            \$opts->{'format'}, 'TAR', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry)});
      $format6->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format6,
            \$opts->{'format'}, 'TXT', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry)});
      $inc1->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($incfp1, \$opts->{'include'}, 1)});
      $inc2->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($incfp2, \$opts->{'include'}, 0)});
      $incfp1->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($incfp1, \$opts->{'incfp'}, 1)});
      $incfp2->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($incfp2, \$opts->{'incfp'}, 0)});
   }else {
      $format1->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format1,
            \$opts->{'format'}, 'PEM', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry, $pass1, $pass2)});
      $format2->signal_connect('toggled' =>
           sub{ &GUI::CALLBACK::toggle_to_var($format2,
            \$opts->{'format'}, 'DER', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry, $pass1, $pass2)});
      $format3->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format3,
            \$opts->{'format'}, 'P12', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry, $pass1, $pass2)});
      $format4->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format4,
            \$opts->{'format'}, 'ZIP', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry, $pass1, $pass2)});
      $format5->signal_connect('toggled' =>
           sub{ GUI::CALLBACK::toggle_to_var($format5,
            \$opts->{'format'}, 'TAR', \$opts->{'outfile'}, 
            \$opts->{'format'}, $fileentry, $pass1, $pass2)});
      $pass1->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($pass1, \$opts->{'nopass'}, 1)});
      $pass2->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($pass2, \$opts->{'nopass'}, 0)});
      $inc1->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($inc1, \$opts->{'include'}, 1)});
      $inc2->signal_connect('toggled' => 
            sub { GUI::CALLBACK::toggle_to_var($inc2, \$opts->{'include'}, 0)});
   }

   $box->show_all();

   return;
}

#
# get export passwd for pkcs#12
#
sub show_p12_export_dialog {
   my ($self, $opts, $mode) = @_;

   my ($box, $label, $table, $entry, $button_ok, $button_cancel, $radiobox,
         $includeca1, $includeca2, $passbox, $pass1, $pass2);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   if($mode eq 'key') {
      $button_ok->signal_connect('clicked', 
         sub { $self->{'KEY'}->get_export_key($self, $opts, $box) });
   } elsif($mode eq 'cert') {
      $button_ok->signal_connect('clicked', 
         sub { $self->{'CERT'}->get_export_cert($self, $opts, $box) });
   }

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Export to PKCS#12"), 
         _("Export to PKCS#12"),
         $button_ok, $button_cancel);

   # small table for storage name
   $table = Gtk2::Table->new(2, 2, 0);
   $box->vbox->add($table);

   $entry = GUI::HELPERS::entry_to_table(_("Key Password:"),
         \$opts->{'passwd'}, $table, 0, 0);
   $entry->grab_focus();

   $entry = GUI::HELPERS::entry_to_table(_("Export Password:"),
      \$opts->{'p12passwd'}, $table, 1, 0);

   $entry = GUI::HELPERS::entry_to_table(_("Friendly Name:"),
      \$opts->{'friendlyname'}, $table, 2, 1);

   $label = GUI::HELPERS::create_label(
         _("Without Passphrase"), 'left', 0, 0);
   $box->vbox->add($label);

   $passbox = Gtk2::HBox->new(0, 0);
   $box->vbox->add($passbox);

   $pass1 = Gtk2::RadioButton->new(undef, _("Yes"));
   $pass1->signal_connect_after('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var(
            $pass1, \$opts->{'nopass'}, 1) });
   $passbox->add($pass1);

   $pass2 = Gtk2::RadioButton->new($pass1, _("No"));
   $pass2->signal_connect_after('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var(
            $pass2, \$opts->{'nopass'}, 0) });
   $passbox->add($pass2);

   if((defined($opts->{'nopass'})) && ($opts->{'nopass'} == 1)) {
      $pass1->set_active(1);
   } else {
      $pass2->set_active(1);
   }

   $label = GUI::HELPERS::create_label(
         _("Add CA Certificate to PKCS#12 structure"), 'left', 0, 0);
   $box->vbox->add($label);

   $radiobox = Gtk2::HBox->new(0, 0);
   $box->vbox->add($radiobox);

   $includeca1 = Gtk2::RadioButton->new(undef, _("Yes"));
   $includeca1->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var(
            $includeca1, \$opts->{'includeca'}, 1) });
   $radiobox->add($includeca1);

   $includeca2 = Gtk2::RadioButton->new($includeca1, _("No"));
   $includeca2->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var(
           $includeca2, \$opts->{'includeca'}, 0) });
   $radiobox->add($includeca2);

   if(defined($opts->{'includeca'}) && $opts->{'includeca'} == 1) {
      $includeca1->set_active(1);
   } else {
      $includeca2->set_active(1);
   }

   $box->show_all();

   return;
}

#
# get data for signing a request
#
sub show_req_sign_dialog {
   my ($self, $opts) = @_;

   my($box, $button_ok, $button_cancel, $entry, $table, $t, $rows, $key1,
         $key2, $radiobox, $label);

   $rows = 0;

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', 
      sub { $self->{'REQ'}->get_sign_req($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Sign Request"), _("Sign Request/Create Certificate"), 
         $button_ok, $button_cancel);

   # small table for data
   $table = Gtk2::Table->new(2, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = GUI::HELPERS::entry_to_table(_("CA Password:"),
         \$opts->{'passwd'}, $table, $rows, 0);
   $rows++;
   $entry->grab_focus();


   $entry = GUI::HELPERS::entry_to_table(_("Valid for (Days):"),
         \$opts->{'days'}, $table, $rows, 1);
   $rows++;

   # print STDERR "DEBUG: got type: $opts->{'type'}\n";

   if($opts->{'type'} eq 'server') {
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}) &&
         $self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} eq 'user') {
         if($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
               eq 'ip'){
            $t = _("Subject alternative name (IP Address):");
         }elsif($self->{TCONFIG}->{'server_cert'}->{'subjectAltNameType'} 
               eq 'dns'){
            $t = _("Subject alternative name (DNS Name):");
         }elsif($self->{TCONFIG}->{'server_cert'}->{'subjectAltNameType'} 
               eq 'raw'){
            $t = _("Subject alternative name (raw):");
         }
         $entry = GUI::HELPERS::entry_to_table($t,
               \$opts->{'subjectAltName'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'}) &&
         $self->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} eq 'user') { 
         $t = _("Extended Key Usage:");
         $entry = GUI::HELPERS::entry_to_table($t,
               \$opts->{'extendedKeyUsage'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'} eq 'user') { 
         $t = _("Netscape SSL Server Name:");
         $entry = GUI::HELPERS::entry_to_table($t, 
               \$opts->{'nsSslServerName'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'} eq 'user') { 
         $t = _("Netscape Revocation URL:");
         $entry = GUI::HELPERS::entry_to_table($t, 
               \$opts->{'nsRevocationUrl'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'} eq 'user') { 
         $t = _("Netscape Renewal URL:");
         $entry = GUI::HELPERS::entry_to_table($t, 
               \$opts->{'nsRenewalUrl'}, $table, $rows, 1);
         $rows++;
      }
   }elsif($opts->{'type'} eq 'client') {
      if(defined($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}) &&
         $self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} eq 'user') {
         if($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
               eq 'ip'){
            $t = _("Subject alternative name (IP Address):");
         }elsif($self->{TCONFIG}->{'client_cert'}->{'subjectAltNameType'} 
               eq 'dns'){
            $t = _("Subject alternative name (DNS Name):");
         }elsif($self->{TCONFIG}->{'client_cert'}->{'subjectAltNameType'} 
               eq 'mail'){
            $t = _("Subject alternative name (eMail Address):");
         }elsif($self->{TCONFIG}->{'client_cert'}->{'subjectAltNameType'} 
               eq 'raw'){
            $t = _("Subject alternative name (raw):");
         }
         $entry = GUI::HELPERS::entry_to_table($t,
               \$opts->{'subjectAltName'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'}) &&
         $self->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} eq 'user') { 
         $t = _("Extended Key Usage:");
         $entry = GUI::HELPERS::entry_to_table($t,
               \$opts->{'extendedKeyUsage'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}) && 
         $self->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'} eq 'user') { 
         $t = _("Netscape Revocation URL:");
         $entry = GUI::HELPERS::entry_to_table($t, 
               \$opts->{'nsRevocationUrl'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}) && 
         $self->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'} eq 'user') { 
         $t = _("Netscape Renewal URL:");
         $entry = GUI::HELPERS::entry_to_table($t, 
               \$opts->{'nsRenewalUrl'}, $table, $rows, 1);
         $rows++;
      }
   }

   # OpenSSL < 0.9.7 was not able to dynamically handle mailadresses in DNs
   if($self->{'OpenSSL'}->{'version'} !~ /^0\.9\.[0-6][a-z]?$/) {
      $radiobox = Gtk2::HBox->new(0, 0);
      $key1 = Gtk2::RadioButton->new(undef, _("Yes"));
      $key1->set_active(1);
      $key1->signal_connect('toggled' =>
           sub{GUI::CALLBACK::toggle_to_var($key1, \$opts->{'noemaildn'}, 0)});
      $radiobox->add($key1);
         
      $key2 = Gtk2::RadioButton->new($key1, _("No"));
      $key2->signal_connect('toggled' =>
           sub{GUI::CALLBACK::toggle_to_var($key2, \$opts->{'noemaildn'}, 1)});
      $radiobox->add($key2);
            
      $label = GUI::HELPERS::create_label(
            _("Add eMail Address to Subject DN:"), 'left', 0, 0);
      $table->attach_defaults($label, 0, 1, $rows, $rows+1);
      $table->attach_defaults($radiobox, 1, 2, $rows, $rows+1);
   }

   $box->show_all();

   return;
}

#
# get data for creating a new CA
#
sub show_ca_dialog {
   my ($self, $opts, $mode) = @_;

   my ($box, $button_ok, $button_cancel, $label, $table, $entry, 
         $catable, $pwtable, $radiobox, $key1, $key2, $key3,
         $key4, $key5);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);
   $button_ok->signal_connect('clicked', 
      sub { $self->{'CA'}->get_ca_create($self, $opts, $box, $mode) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   if(defined($mode) && $mode eq "sub") {
      $box = GUI::HELPERS::dialog_box(
            _("Create CA"), _("Create a new Sub CA"),
            $button_ok, $button_cancel);
   } else {
      $box = GUI::HELPERS::dialog_box(
            _("Create CA"), _("Create a new CA"),
            $button_ok, $button_cancel);
   }

   $button_ok->grab_default();

   if(defined($mode) && $mode eq "sub") {
      # small table for ca-password
      $pwtable = Gtk2::Table->new(1, 2, 0);
      $pwtable->set_col_spacing(0, 10);
      $box->vbox->add($pwtable);
   
      $entry = GUI::HELPERS::entry_to_table(
            _("CA Password (for creating the new CA):"),
            \$opts->{'parentpw'}, $pwtable, 0, 0);
      $entry->grab_focus();
   }

   # small table for storage name
   $table = Gtk2::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = GUI::HELPERS::entry_to_table(
         _("Name (for local storage):"),
         \$opts->{'name'}, $table, 0, 1);
   if(not defined($mode)) {
      $entry->grab_focus();
   }

   $label = GUI::HELPERS::create_label(
         _("Data for CA Certificate"), 'left', 0, 0);
   $box->vbox->add($label);

   # table for ca data
   $catable = Gtk2::Table->new(1, 13, 0);
   $catable->set_col_spacing(0, 10);
   $box->vbox->add($catable);

   $entry = GUI::HELPERS::entry_to_table(
         _("Common Name (for the CA):"),
         \$opts->{'CN'}, $catable, 0, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Country Name (2 letter code):"),
         \$opts->{'C'}, $catable, 1, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Password (needed for signing):"),
         \$opts->{'passwd'}, $catable, 2, 0);

   $entry = GUI::HELPERS::entry_to_table(
         _("Password (confirmation):"),
         \$opts->{'passwd2'}, $catable, 3, 0);

   $entry = GUI::HELPERS::entry_to_table(
         _("State or Province Name:"),
         \$opts->{'ST'}, $catable, 4, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Locality Name (eg. city):"),
         \$opts->{'L'}, $catable, 5, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Organization Name (eg. company):"),
         \$opts->{'O'}, $catable, 6, 1);

   $entry = GUI::HELPERS::entry_to_table(
      _("Organizational Unit Name (eg. section):"),
      \$opts->{'OU'}->[0], $catable, 7, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("eMail Address").":",
         \$opts->{'EMAIL'}, $catable, 8, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("Valid for (Days):"),
         \$opts->{'days'}, $catable, 9, 1);

   $label = GUI::HELPERS::create_label(
         _("Keylength").":", 'left', 0, 0);
   $catable->attach_defaults($label, 0, 1, 10, 11);

   $radiobox = Gtk2::HBox->new(0, 0);
   $key1 = Gtk2::RadioButton->new(undef, '1024');
   $key1->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var($key1, \$opts->{'bits'}, 1024)});
   $radiobox->add($key1);

   $key2 = Gtk2::RadioButton->new($key1, '2048');
   $key2->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var($key2, \$opts->{'bits'}, 2048)});
   $radiobox->add($key2);

   $key3 = Gtk2::RadioButton->new($key1, '4096');
   $key3->signal_connect('toggled' => 
         sub { GUI::CALLBACK::toggle_to_var($key3, \$opts->{'bits'}, 4096)});
   $radiobox->add($key3);

   # set default
   if(defined($opts->{'bits'}) && $opts->{'bits'} == 1024) {
      $key1->set_active(1);
   } elsif (defined($opts->{'bits'}) && $opts->{'bits'} == 2048) { 
      $key2->set_active(1);
   } elsif (defined($opts->{'bits'}) && $opts->{'bits'} == 4096) { 
      $key3->set_active(1);
   }

   $catable->attach_defaults($radiobox, 1, 2, 10, 11);

   $label = GUI::HELPERS::create_label(_("Digest").":", 'left', 0, 0);
   $catable->attach_defaults($label, 0, 1, 15, 16);

   $radiobox = Gtk2::HBox->new(0, 0);
   &_fill_radiobox($radiobox, \$opts->{'digest'}, %md_algorithms);
   $catable->attach_defaults($radiobox, 1, 2, 15, 16);

   $box->show_all();

   return;
}

#
# get data for importing a new CA
#
sub show_ca_import_dialog {
   my ($self, $opts) = @_;

   my ($box, $button, $button_ok, $button_cancel, $label, $table, $filetable,
         $pwtable, $entry, $certentry, $keyentry, $direntry, $indexentry);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);
   $button_ok->signal_connect('clicked', 
      sub { $self->{'CA'}->get_ca_import($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box( 
         _("Import CA"), _("Import an existing CA into TinyCA"),
         $button_ok, $button_cancel);

   $button_ok->grab_default();

   # small table for old ca-password
   $pwtable = Gtk2::Table->new(1, 2, 0);
   $pwtable->set_col_spacing(0, 10);
   $box->vbox->add($pwtable);
   
   $entry = GUI::HELPERS::entry_to_table(
         _("Password of the private CA key (Needed for import):"),
         \$opts->{'passwd'}, $pwtable, 0, 0);
   $entry->grab_focus();

   # small table for storage name and new passwords
   $table = Gtk2::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = GUI::HELPERS::entry_to_table(
         _("Name (for local storage):"),
         \$opts->{'name'}, $table, 0, 1);

   $entry = GUI::HELPERS::entry_to_table(
         _("New password for the CA:"),
         \$opts->{'newpasswd'}, $table, 1, 0);

   $entry = GUI::HELPERS::entry_to_table(
         _("Confirm password:"),
         \$opts->{'newpasswd2'}, $table, 2, 0);

   # table for file selection dialogs
   $label = GUI::HELPERS::create_label(
         _("Files/Directories to import"), 'center', 0, 1);
   $box->vbox->add($label);

   $filetable = Gtk2::Table->new(1, 3, 0);
   $box->vbox->add($filetable);

   # CA certificate
   $label = GUI::HELPERS::create_label(
         _("CA Certificate (PEM/DER):"), 'left', 0, 0);
   $filetable->attach_defaults($label, 0, 1, 0, 1);

   $certentry = Gtk2::Entry->new();
   $filetable->attach_defaults($certentry, 1, 2, 0, 1);
   $certentry->set_text($opts->{'cacertfile'})
      if(defined($opts->{'cacertfile'}));
   $certentry->signal_connect( 'changed' =>
        sub { GUI::CALLBACK::entry_to_var(
           $certentry, $certentry, \$opts->{'cacertfile'}) });

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' =>
      sub{ GUI::HELPERS::browse_file(
         _("Import CA Certificate"), $certentry, 'open') });
   $filetable->attach_defaults($button, 2, 3, 0, 1);

   # CA private key
   $label = GUI::HELPERS::create_label(
         _("CA private key (PEM/DER):"), 'left', 0, 0);
   $filetable->attach_defaults($label, 0, 1, 1, 2);

   $keyentry = Gtk2::Entry->new();
   $filetable->attach_defaults($keyentry, 1, 2, 1, 2);
   $keyentry->set_text($opts->{'cakeyfile'})
      if(defined($opts->{'cakeyfile'}));
   $keyentry->signal_connect( 'changed' =>
        sub { GUI::CALLBACK::entry_to_var(
           $keyentry, $keyentry, \$opts->{'cakeyfile'}) });

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' =>
      sub{ GUI::HELPERS::browse_file(
         _("Import CA private Key"), $keyentry, 'open') });
   $filetable->attach_defaults($button, 2, 3, 1, 2);

   # Index file
   $label = GUI::HELPERS::create_label(
         _("OpenSSL Index File (index.txt):"), 'left', 0, 0);
   $filetable->attach_defaults($label, 0, 1, 2, 3);

   $indexentry = Gtk2::Entry->new();
   $filetable->attach_defaults($indexentry, 1, 2, 2, 3);
   $indexentry->set_text($opts->{'indexfile'})
      if(defined($opts->{'indexfile'}));
   $indexentry->signal_connect( 'changed' =>
     sub { GUI::CALLBACK::entry_to_var(
        $indexentry, $indexentry, \$opts->{'indexfile'}) });

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' =>
      sub{ GUI::HELPERS::browse_file(
         _("Import Index File"), $indexentry, 'open') });
   $filetable->attach_defaults($button, 2, 3, 2, 3);

   # certificate directory
   $label = GUI::HELPERS::create_label(
         _("Directory containing certificates (PEM/DER):"), 'left', 0, 0);
   $filetable->attach_defaults($label, 0, 1, 3, 4);

   $direntry = Gtk2::Entry->new();
   $filetable->attach_defaults($direntry, 1, 2, 3, 4);
   $direntry->set_text($opts->{'certdir'})
      if(defined($opts->{'certdir'}));
   $direntry->signal_connect( 'changed' =>
         sub { GUI::CALLBACK::entry_to_var(
            $direntry, $direntry, \$opts->{'certdir'}) });

   $button = Gtk2::Button->new(_("Browse..."));
   $button->signal_connect('clicked' =>
      sub{ GUI::HELPERS::browse_file(
         _("Import Certificates from directory"), $direntry, 'open') });
   $filetable->attach_defaults($button, 2, 3, 3, 4);

   $box->show_all();

   return;
}

#
# subroutines for pop-up boxes
# 
sub show_help {
   my $self = shift;

   GUI::HELPERS::print_info(_("You are kidding, are you??"));

   return;
}

#
#  About dialog
#
sub about {
   my $self = shift;
   my $main = shift;

   my ($aboutdialog, $href, $label);

   $aboutdialog = Gtk2::AboutDialog->new();
   $aboutdialog->set_name("TinyCA2");
   $aboutdialog->set_version($main->{'version'});
   $aboutdialog->set_copyright("2002-2006 Stephan Martin");
   $aboutdialog->set_license("GNU Public License (GPL)");
   $aboutdialog->set_website("http://tinyca.sm-zone.net/");
   $aboutdialog->set_authors("Stephan Martin <sm\@sm-zone.net>");
   $aboutdialog->set_translator_credits(
         _("Czech: Robert Wolf <gentoo\@slave.umbr.cas.cz>")."\n".
         _("Swedish: Daniel Nylander <yeager\@lidkoping.net>")."\n".
         _("Spanish: Ramon Pons Vivanco <rpons\@rinu.org>")."\n".
         _("French: Thibault Le Meur <Thibault.Lemeur\@supelec.fr>"));

   $aboutdialog->show_all();

   return;
}

#
# get confirmation for deleting a request
#
sub show_del_confirm {
   my ($self, $file, $type) = @_;

   my($t, $button_ok, $button_cancel, $box);

   if($type eq 'req') {
      $t = _("Do you really want to delete the selected Request?");
   }elsif($type eq 'key') {
      $t = _("Do you really want to delete the selected Key?");
   }elsif($type eq 'cert') {
      $t = _("Do you really want to delete the selected Certificate?");
   }else{
      GUI::HELPERS::print_error("Invalid type in show_del_confirm(): ".$type);
   }

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   if($type eq 'req') {
      $button_ok->signal_connect('clicked', sub { 
           $self->{'REQ'}->del_req($self, $file);
           $box->destroy() });
   }elsif($type eq 'key') {
      $button_ok->signal_connect('clicked', sub { 
           $self->{'KEY'}->del_key($self, $file);
           $box->destroy() });
   }elsif($type eq 'cert') {
      $button_ok->signal_connect('clicked', sub {
            $self->{'CERT'}->del_cert($self, $file);
            $box->destroy() });
   }

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy(); return });
      
   $box = Gtk2::MessageDialog->new(
          undef, [qw/destroy-with-parent modal/], 'question', 'none', $t);

   $box->add_action_widget($button_ok, 0);
   $box->add_action_widget($button_cancel, 1);

   $box->show_all();
}

#
# show warning - overwrite key
#
sub show_req_overwrite_warning {
   my ($self, $opts) = @_;

   my ($box, $actionarea, $button_ok, $button_cancel, $label);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked' => 
         sub { $self->{'REQ'}->create_req($self, $opts); 
               $box->destroy() });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->can_default(1);
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Overwrite Request/Key"), _("Overwrite Request/Key"),
         $button_ok, $button_cancel);

   $button_cancel->grab_default();

   $label = GUI::HELPERS::create_label(
         _("The Key or the Request is already existing!"), 
         'center', 1, 0);
   $box->vbox->add($label);

   $label = GUI::HELPERS::create_label(
         _("You won't be able to sign this Request"), 
         'center', 1, 0);
   $box->vbox->add($label);

   $label = GUI::HELPERS::create_label(
         _("if the corresponding certificate is still valid"), 
         'center', 1, 0);
   $box->vbox->add($label);

   $box->show_all();

   return;
}

#
# show warning - certificate expiration date
#
sub show_req_date_warning {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $t);

   $t = _("The Certificate will be longer valid than your CA!");
   $t .= "\n";
   $t .= _("This may cause problems with some software!!");

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', 
         sub { $opts->{'ignoredate'} = 'true';
               $self->{'REQ'}->get_sign_req($self, $opts, $box); });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { 
         $self->show_req_sign_dialog($opts);
         $box->destroy();
         });
   $button_cancel->can_default(1);

   $box = GUI::HELPERS::dialog_box(
         _("Expirationdate Warning"), $t,
         $button_ok, $button_cancel);

   $button_cancel->grab_default();

   $box->show_all();
}

#
# show CA history
#
sub show_history {
   my $self = shift;

   my ($box, $button_ok, @index, $list, $list_scrolled, $store, @titles,
         $column, $t, $iter, $dn, $state, $expdate, $revdate, $renderer);

   @index =
      $self->{'OpenSSL'}->read_index($self->{'CA'}->{'cadir'}."/index.txt");

   $list_scrolled = Gtk2::ScrolledWindow->new(undef, undef);
   $list_scrolled->set_policy('automatic', 'automatic');
   $list_scrolled->set_shadow_type('etched-in');
   $store = Gtk2::ListStore->new(
         'Glib::String',  # common name
         'Glib::String',  # status
         'Glib::String',  # serial
         'Glib::String',  # expiration
         'Glib::String',  # revocation
         'Glib::String'   # reason
         );

   $list = Gtk2::TreeView->new_with_model($store);
   $list->get_selection->set_mode('none');
   @titles = ( 
         _("Serial"),
         _("Common Name"),
         _("Status"),
         _("Expiration Date"),
         _("Revocation Date"),
         _("Revocation Reason")
         );

   for (my $i = 0; $titles[$i]; $i++) {
      $renderer = Gtk2::CellRendererText->new();
      $column = Gtk2::TreeViewColumn->new_with_attributes( 
            $titles[$i], $renderer, 'text' => $i);
      $column->set_sort_column_id($i);
      $column->set_resizable(1);
      if ($i == 2) {
         $column->set_cell_data_func ($renderer, sub {
               my ($column, $cell, $model, $iter) = @_;
               my $text = $model->get($iter, 2);
               my $color = $text eq _("VALID")?'green':'red';
               $cell->set (text => $text, foreground => $color);
               });
      }
      $list->append_column($column);
   }

   foreach my $tmp (@index) {
      $iter = $store->append();
      $dn   = HELPERS::parse_dn($tmp->{'DN'});
      if($tmp->{'STATUS'} eq 'V') {
         $state = _("VALID");
      } elsif($tmp->{'STATUS'} eq 'E') {
         $state = _("EXPIRED");
      } elsif($tmp->{'STATUS'} eq 'R') {
         $state = _("REVOKED");
      }

      $expdate = strftime("%F", localtime($tmp->{'EXPDATE'}));
      if(defined($tmp->{'REVDATE'})) {
         $revdate = strftime("%F", localtime($tmp->{'REVDATE'}));
      }

      $store->set($iter,
            0 => $tmp->{'SERIAL'},
            1 => $dn->{'CN'},
            2 => $state,
            3 => $expdate,
            4 => $revdate,
            5 => $tmp->{'REVREASON'}
            );
   }

   $list_scrolled->add_with_viewport($list);

   $t = _("CA History");
   
   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->can_default(1);
   $button_ok->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box($t, $t, $button_ok);
   $box->set_default_size(700, 400);

   $button_ok->grab_default();

   $box->vbox->add($list_scrolled);

   $box->show_all();
}

#
# get confirmation for overwriting certificate
#
sub show_cert_overwrite_confirm {
   my ($self, $opts) = @_;

   my($box, $button_ok, $button_cancel, $label);
   
   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', 
         sub { $opts->{'overwrite'} = 'true';
               $self->{'REQ'}->get_sign_req($self, $opts, $box) });

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->can_default(1);
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("Overwrite Certificate"), _("Overwrite Certificate"),
         $button_ok, $button_cancel);

   $button_cancel->grab_default();

   $label = GUI::HELPERS::create_label(
      _("There seems to be a certificate with the same Subject already."),
      'center', 1, 0);
   $box->vbox->add($label);

   $label = GUI::HELPERS::create_label(
         _("Creating a new one (overwrite) will fail if it\'s not revoked or expired!"), 
         'center', 1, 0);
   $box->vbox->add($label);


   $label = GUI::HELPERS::create_label(
         _("Really try to overwrite the Certificate?"), 'center', 1, 0);
   $box->vbox->add($label);

   $box->show_all();
   return;
}

#
# ask if the CA shall be converted
#
sub show_ca_convert_dialog {
   my ($self, $opts) = @_;

   my($box, $label, $button_ok, $button_cancel, $t);

   $button_ok = Gtk2::Button->new_from_stock('gtk-ok');
   $button_ok->signal_connect('clicked', 
         sub { 
            $opts->{'doconv'} = 1;
            $self->{'CA'}->open_ca($self, $opts, $box) 
         }
   );
   $button_ok->can_default(1);

   $button_cancel = Gtk2::Button->new_from_stock('gtk-cancel');
   $button_cancel->signal_connect('clicked', 
         sub { 
            $opts->{'noconv'} = 1;
            $self->{'CA'}->open_ca($self, $opts, $box) 
         }
   );

   $box = GUI::HELPERS::dialog_box(
         _("Convert CA"), _("Convert CA"),
         $button_ok, $button_cancel);

   $button_ok->grab_default();

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $t = _("This CA seems to be created with openssl 0.9.6x. And it seems like you have switched to openssl 0.9.7x.");

   $label = GUI::HELPERS::create_label($t, 'center', 1, 0);
   $box->vbox->add($label);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $t = _("You won't be able to revoke the existing certificates without converting the index file of this CA to the new format.");

   $label = GUI::HELPERS::create_label($t, 'center', 1, 0);
   $box->vbox->add($label);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $t = _("Attention: it will not be easy to switch back, this has to be done manually");
   $label = GUI::HELPERS::create_label($t, 'center', 1, 0);
   $box->vbox->add($label);

   $box->show_all();

   return;
}

#
# create popup menu for keys
#
sub _create_key_menu {
   my $self = shift;

   my ($item, $image);

   $self->{'keymenu'} = Gtk2::Menu->new();

   $item = Gtk2::ImageMenuItem->new( _("Export Key"));
   $item->signal_connect(activate => 
         sub { $self->{'KEY'}->get_export_key($self) });
   $image = Gtk2::Image->new_from_stock('gtk-save', 'menu');
   $item->set_image($image);
   $self->{'keymenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Delete Key"));
   $item->signal_connect(activate => 
         sub { $self->{'KEY'}->get_del_key($self) });
   $image = Gtk2::Image->new_from_stock('gtk-delete', 'menu');
   $item->set_image($image);
   $self->{'keymenu'}->insert($item, -1);

   $self->{'keymenu'}->show_all();

   return;
}

#
# create popup menus for certificates
#
sub _create_cert_menu {
   my $self = shift;

   my ($item, $image);

   $self->{'certmenu'} = Gtk2::Menu->new();

   $item = Gtk2::ImageMenuItem->new( _("Certificate Details"));
   $item->signal_connect(activate => 
         sub { $self->show_details('cert') });
   $image = Gtk2::Image->new_from_stock('gtk-new', 'menu');
   $item->set_image($image);
   $self->{'certmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("View Certificate"));
   $item->signal_connect(activate => 
         sub { $self->show_text('cert') });
   $image = Gtk2::Image->new_from_stock('gtk-find', 'menu');
   $item->set_image($image);
   $self->{'certmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Export Certificate"));
   $item->signal_connect(activate => 
         sub { $self->{'CERT'}->get_export_cert($self) });
   $image = Gtk2::Image->new_from_stock('gtk-save', 'menu');
   $item->set_image($image);
   $self->{'certmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Revoke Certificate"));
   $item->signal_connect(activate => 
         sub { $self->{'CERT'}->get_revoke_cert($self) });
   $image = Gtk2::Image->new_from_stock('gtk-stop', 'menu');
   $item->set_image($image);
   $self->{'certmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Renew Certificate"));
   $item->signal_connect(activate => 
         sub { $self->{'renewcertmenu'}->popup(
                           undef, undef, undef, undef, 1, 0) });
   $image = Gtk2::Image->new_from_stock('gtk-refresh', 'menu');
   $item->set_image($image);
   $self->{'certmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Delete Certificate"));
   $item->signal_connect(activate => 
         sub { $self->{'CERT'}->get_del_cert($self) });
   $image = Gtk2::Image->new_from_stock('gtk-delete', 'menu');
   $item->set_image($image);
   $self->{'certmenu'}->insert($item, -1);

   $self->{'certmenu'}->show_all();

   return;
}

#
# create popup menus for creating certificates
#
sub _create_create_cert_menu {
   my $self = shift;
   
   my ($item);

   $self->{'newcertmenu'} = Gtk2::Menu->new();

   $item = Gtk2::MenuItem->new( 
         _("Create Key and Certificate (Server)"));
   $item->signal_connect(activate => 
         sub { $self->{'REQ'}->get_req_create($self, "signserver") });
   $self->{'newcertmenu'}->insert($item, 0);

   $item = Gtk2::MenuItem->new( 
         _("Create Key and Certificate (Client)"));
   $item->signal_connect(activate => 
         sub { $self->{'REQ'}->get_req_create($self, "signclient") });
   $self->{'newcertmenu'}->insert($item, 1);

   $self->{'newcertmenu'}->show_all();

   return;
}

#
# create popup menus for sign request button
#
sub _create_renew_cert_menu {
   my $self = shift;
   
   my ($item, $opts);

   $self->{'renewcertmenu'} = Gtk2::Menu->new();

   $item = Gtk2::MenuItem->new( 
         _("Renew Certificate (Server)"));
   $item->signal_connect(activate => 
         sub { $opts->{'type'} = 'server';
               $self->{'CERT'}->get_renew_cert($self, $opts) });
   $self->{'renewcertmenu'}->insert($item, 0);

   $item = Gtk2::MenuItem->new( 
         _("Renew Certificate (Client)"));
   $item->signal_connect(activate => 
         sub { $opts->{'type'} = 'client';
               $self->{'CERT'}->get_renew_cert($self, $opts) });
   $self->{'renewcertmenu'}->insert($item, 1);

   $self->{'renewcertmenu'}->show_all();

   return;
}

#
# create popup menus for sign request button
#
sub _create_sign_req_menu {
   my $self = shift;
   
   my ($item, $opts);

   $self->{'reqsignmenu'} = Gtk2::Menu->new();

   $item = Gtk2::MenuItem->new( 
         _("Sign Request (Server)"));
   $item->signal_connect(activate => 
         sub { $opts->{'type'} = 'server';
               $self->{'REQ'}->get_sign_req($self, $opts) });
   $self->{'reqsignmenu'}->insert($item, 0);

   $item = Gtk2::MenuItem->new( 
         _("Sign Request (Client)"));
   $item->signal_connect(activate => 
         sub { $opts->{'type'} = 'client';
               $self->{'REQ'}->get_sign_req($self, $opts) });
   $self->{'reqsignmenu'}->insert($item, 1);

   $self->{'reqsignmenu'}->show_all();

   return;
}

#
# create popup menus for requests
#
sub _create_req_menu {
   my $self = shift;
   
   my ($item, $opts, $image);

   $self->{'reqmenu'} = Gtk2::Menu->new();

   $item = Gtk2::ImageMenuItem->new( _("Request Details"));
   $item->signal_connect(activate => 
         sub { $self->show_details('req') });
   $image = Gtk2::Image->new_from_stock('gtk-find', 'menu');
   $item->set_image($image);
   $self->{'reqmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("View Request"));
   $item->signal_connect(activate => 
         sub { $self->show_text('req') });
   $image = Gtk2::Image->new_from_stock('gtk-find', 'menu');
   $item->set_image($image);
   $self->{'reqmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("New Request"));
   $item->signal_connect(activate => 
         sub { $self->{'REQ'}->get_req_create($self) });
   $image = Gtk2::Image->new_from_stock('gtk-new', 'menu');
   $item->set_image($image);
   $self->{'reqmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Import Request"));
   $item->signal_connect(activate => 
         sub { $self->{'REQ'}->get_import_req($self) });
   $image = Gtk2::Image->new_from_stock('gtk-revert-to-saved', 'menu');
   $item->set_image($image);
   $self->{'reqmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Sign Request"));
   $item->signal_connect(activate => 
         sub { $self->{'reqsignmenu'}->popup( 
            undef, undef, undef, undef, 1, 0) });
   $image = Gtk2::Image->new_from_stock('gtk-properties', 'menu');
   $item->set_image($image);
   $self->{'reqmenu'}->insert($item, -1);

   $item = Gtk2::ImageMenuItem->new( _("Delete Request"));
   $item->signal_connect(activate => 
         sub { $self->{'REQ'}->get_del_req($self) });
   $image = Gtk2::Image->new_from_stock('gtk-delete', 'menu');
   $item->set_image($image);
   $self->{'reqmenu'}->insert($item, -1);

   $self->{'reqmenu'}->show_all();

   return;
}

sub _fill_radiobox {
   my($radiobox, $var, %values) = @_;
   my($previous_key, $value);

   $previous_key = undef;
   for $value (keys %values) {
      my $display_name = $values{$value};
      my $key = Gtk2::RadioButton->new($previous_key, $display_name);
      $key->set_active(1) if(defined($$var) && $$var eq $value);
      $key->signal_connect('toggled' =>
			   sub{GUI::CALLBACK::toggle_to_var($key, $var, $value)});
      $radiobox->add($key);
      $previous_key = $key;
   }
}

1
