# Copyright (c) Olaf Gellert <og@pre-secure.de> and
#               Stephan Martin <sm@sm-zone.net>
#
# $Id: X509_browser.pm,v 1.6 2006/06/28 21:50:42 sm Exp $
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
package GUI::X509_browser;

use HELPERS;
use GUI::HELPERS;
use GUI::X509_infobox;

use POSIX;

my $tmpdefault="/tmp";

my $version = "0.1";
my $true = 1;
my $false = undef;

sub new {
   my $that = shift;
   my $self = {};

   $self->{'main'} = shift;
   my $mode = shift;

   my ($font, $fontfix);

   my $class = ref($that) || $that;


   if ((defined $mode) && 
         (($mode eq 'cert') || ($mode eq 'req') || ($mode eq 'key'))) {
      $self->{'mode'} = $mode;
   } else {
      printf STDERR "No mode specified for X509browser\n";
      return undef;
   }

   # initialize fonts and styles
   $font    = Gtk2::Pango::FontDescription->from_string(
         "-adobe-helvetica-bold-r-normal--*-120-*-*-*-*-*-*");
   if(defined($font)) {
      $self->{'stylebold'} = Gtk2::Style->new();
      $self->{'stylebold'}->font_desc->from_string(
            "-adobe-helvetica-bold-r-normal--*-120-*-*-*-*-*-*");
   } else {
      $self->{'stylebold'} = undef;
   }

   $fontfix = Gtk2::Pango::FontDescription->from_string(
         "-adobe-courier-medium-r-normal--*-100-*-*-*-*-*-*");
   if(defined($fontfix)) {
      $self->{'stylefix'} = Gtk2::Style->new();
      $self->{'stylefix'}->font_desc->from_string(
            "-adobe-courier-medium-r-normal--*-100-*-*-*-*-*-*");
   } else {
      $self->{'stylefix'} = undef;
   }

   bless($self, $class);

   $self;
}


# sub create_window {
#    my ($self, $title, $ok_text, $cancel_text,
# 	      $ok_function, $cancel_function) = @_;
# 
#    my ($button_ok, $button_cancel);
# 
#    if ( $self->{'dialog_shown'} == $true ) {
#      return(undef);
#      }
# 
#    # check arguments
#    if ($title eq undef) {
#      $title = "CA browser, V$version";
#      }
# 
#    if (not defined($ok_text)) {
#      $ok_text = _("OK");
#      }
#    if (not defined($cancel_text)) {
#      $cancel_text = _("Cancel");
#      }
# 
#    # initialize main window
#    $self->{'window'} = new Gtk::Dialog();
# 
#    # $self->{'window'}->set_policy($false,$false,$true);
# 
#    # store pointer to vbox as "browser widget"
#    $self->{'browser'}=$self->{'window'}->vbox;
# 
#    if (defined $ok_function) {
#       # todo: we should check if this is a function reference
#       $self->{'User_OK_function'} = $ok_function;
#       }
#    $self->{'OK_function'} = sub { $self->ok_function(); };
# 
#    if (defined $cancel_function) {
#       # todo: we should check if this is a function reference
#       $self->{'User_CANCEL_function'} = $cancel_function;
#       }
#    $self->{'CANCEL_function'} = sub { $self->cancel_function(); };
# 
# 
# 
#    $button_ok = new Gtk::Button( "$ok_text" );
#    $button_ok->signal_connect( "clicked", $self->{'OK_function'});
#    $self->{'window'}->action_area->pack_start( $button_ok, $true, $true, 0 );
# 
#    $button_cancel = new Gtk::Button( "$cancel_text" );
#    $button_cancel->signal_connect('clicked', $self->{'CANCEL_function'});
#    $self->{'window'}->action_area->pack_start( $button_cancel, $true, $true, 0 );
# 
#    $self->{'window'}->set_title( "$title" );
# 
#    $self->{'window'}->show_all();
# 
# }

sub set_window {
  my $self = shift;
  my $widget = shift;

  if ( (not defined $self->{'browser'}) || ( $self->{'browser'} == undef )) {
     $self->{'browser'}=$widget;
  } else {
     # browser widget already exists
     return $false;
  }
}

sub add_list {
   my ($self, $actca, $directory, $crlfile, $indexfile) = @_;

   my ($x509listwin, @titles, @certtitles, @reqtitles, @keytitles, $column,
         $color, $text, $iter, $renderer);

   # printf STDERR "AddList: Self: $self, Dir $directory, CRL $crlfile, Index: $indexfile\n";

   @reqtitles = (_("Common Name"),
                 _("eMail Address"),
                 _("Organizational Unit"),
                 _("Organization"),
                 _("Location"),
                 _("State"),
                 _("Country"));

   @certtitles = (_("Common Name"),
                  _("eMail Address"),
                  _("Organizational Unit"),
                  _("Organization"),
                  _("Location"),
                  _("State"),
                  _("Country"),
                  _("Status"));

   @keytitles = (_("Common Name"),
                 _("eMail Address"),
                 _("Organizational Unit"),
                 _("Organization"),
                 _("Location"),
                 _("State"),
                 _("Country"),
                 _("Type"));

   $self->{'actca'}    = $actca;
   $self->{'actdir'}   = $directory;
   $self->{'actcrl'}   = $crlfile;
   $self->{'actindex'} = $indexfile;
 
   if(defined($self->{'x509box'})) {
      $self->{'browser'}->remove($self->{'x509box'});
      $self->{'x509box'}->destroy();
   }
 
   $self->{'x509box'} = Gtk2::VBox->new(0, 0);

   # pane for list (top) and cert infos (bottom)
   $self->{'x509pane'} = Gtk2::VPaned->new();
   $self->{'x509pane'}->set_position(250);
   $self->{'x509box'}->add($self->{'x509pane'});
 
   $self->{'browser'}->pack_start($self->{'x509box'}, 1, 1, 0);
 
   # now the list
   $x509listwin = Gtk2::ScrolledWindow->new(undef, undef);
   $x509listwin->set_policy('automatic', 'automatic');
   $x509listwin->set_shadow_type('etched-in');
   $self->{'x509pane'}->pack1($x509listwin, 1, 1);
 
   # shall we display certificates, requests or keys?
   if ((defined $self->{'mode'}) && ($self->{'mode'} eq "cert")) { 
      
      $self->{'x509store'} = Gtk2::ListStore->new(
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::Int');
 
      @titles = @certtitles;
 
   } elsif ((defined $self->{'mode'}) && ($self->{'mode'} eq "req")) {
 
      $self->{'x509store'} = Gtk2::ListStore->new(
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::Int');
 
      @titles = @reqtitles;
 
   } elsif ((defined $self->{'mode'}) && ($self->{'mode'} eq "key")) {
       
      $self->{'x509store'} = Gtk2::ListStore->new(
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::Int');
 
      @titles = @keytitles;

   } else {
     # undefined mode
      return undef;
   }
 
   $self->{'x509store'}->set_sort_column_id(0, 'ascending');
     
   $self->{'x509clist'} = Gtk2::TreeView->new_with_model($self->{'x509store'});
   $self->{'x509clist'}->get_selection->set_mode ('single');
 
   for(my $i = 0; $titles[$i]; $i++) {
      $renderer = Gtk2::CellRendererText->new();
      $column = Gtk2::TreeViewColumn->new_with_attributes( 
            $titles[$i], $renderer, 'text' => $i); 
      $column->set_sort_column_id($i);
      $column->set_resizable(1);
      if (($i == 7) && ($self->{'mode'} eq 'cert')) {
         $column->set_cell_data_func ($renderer, sub {
               my ($column, $cell, $model, $iter) = @_;
               $text = $model->get($iter, 7);
               $color = $text eq _("VALID")?'green':'red';
               $cell->set (text => $text, foreground => $color);
               });
      }
      $self->{'x509clist'}->append_column($column); 
   }

   if ((defined $self->{'mode'}) && ($self->{'mode'} eq 'cert')) {
      $self->{'x509clist'}->get_selection->signal_connect('changed' => 
            sub { _fill_info($self, 'cert') });
   } elsif ((defined $self->{'mode'}) && ($self->{'mode'} eq 'req')) {
      $self->{'x509clist'}->get_selection->signal_connect('changed' => 
            sub { _fill_info($self, 'req') });
   }

   $x509listwin->add($self->{'x509clist'});
 
   update($self, $directory, $crlfile, $indexfile, $true);
 
}

sub update {
  my ($self, $directory, $crlfile, $indexfile, $force) = @_;

  $self->{'actdir'}   = $directory;
  $self->{'actcrl'}   = $crlfile;
  $self->{'actindex'} = $indexfile;

  # print STDERR "DEBUG: set new dir: $self->{'actdir'}\n";

  if ($self->{'mode'} eq "cert") {
     update_cert($self, $directory, $crlfile, $indexfile, $force);
  } elsif ($self->{'mode'} eq "req") {
     update_req($self, $directory, $crlfile, $indexfile, $force);
  } elsif ($self->{'mode'} eq "key") {
     update_key($self, $directory, $crlfile, $indexfile, $force);
  } else {
     return undef;
  }

  if ((defined $self->{'infowin'}) && ($self->{'infowin'} ne "")) {
     update_info($self);
  }

  $self->{'browser'}->show_all();

  return($true);
}

sub update_req {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind, $name, $state, @line, $iter);

    $self->{'main'}->{'REQ'}->read_reqlist(
          $directory, $crlfile, $indexfile, $force, $self->{'main'});

    $self->{'x509store'}->clear();

    $ind = 0;
    foreach my $n (@{$self->{'main'}->{'REQ'}->{'reqlist'}}) {
      ($name, $state) = split(/\%/, $n);
      @line = split(/\:/, $name);
      $iter = $self->{'x509store'}->append();
      $self->{'x509store'}->set($iter, 
            0 => $line[0], 
            1 => $line[1], 
            2 => $line[2],
            3 => $line[3], 
            4 => $line[4], 
            5 => $line[5], 
            6 => $line[6], 
            7 => $ind);
      $ind++; 
    }
     # now select the first row to display certificate informations
     $self->{'x509clist'}->get_selection->select_path(
           Gtk2::TreePath->new_first());

}

sub update_cert {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind, $name, $state, @line, $iter);

    $self->{'main'}->{'CERT'}->read_certlist(
          $directory, $crlfile, $indexfile, $force, $self->{'main'});

    $self->{'x509store'}->clear();

    $ind = 0;
    foreach my $n (@{$self->{'main'}->{'CERT'}->{'certlist'}}) {
       ($name, $state) = split(/\%/, $n);
       @line = split(/\:/, $name);
       $iter = $self->{'x509store'}->append();
       $self->{'x509store'}->set($iter, 
             0 => $line[0], 
             1 => $line[1], 
             2 => $line[2],
             3 => $line[3], 
             4 => $line[4], 
             5 => $line[5], 
             6 => $line[6], 
             7 => $state, 
             8 => $ind);

       
#       $self->{'x509clist'}->set_text($row, 7, $state);
#       if($state eq _("VALID")) {
#          $self->{'x509clist'}->set_cell_style($row, 7, $self->{'stylegreen'});
#       } else {
#          $self->{'x509clist'}->set_cell_style($row, 7, $self->{'stylered'});
#       }
#       $self->{'x509clist'}->set_text($row, 8, $ind);
        $ind++;
     }
     # now select the first row to display certificate informations
     $self->{'x509clist'}->get_selection->select_path(
           Gtk2::TreePath->new_first());
}

sub update_key {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind, $name, @line, $iter, $state);

    $self->{'main'}->{'KEY'}->read_keylist($self->{'main'});

    $self->{'x509store'}->clear();

    $ind = 0;
    foreach my $n (@{$self->{'main'}->{'KEY'}->{'keylist'}}) {
       ($name, $state) = split(/\%/, $n);
       @line = split(/\:/, $name);
       $iter = $self->{'x509store'}->append();
       $self->{'x509store'}->set($iter, 
             0 => $line[0], 
             1 => $line[1], 
             2 => $line[2],
             3 => $line[3], 
             4 => $line[4], 
             5 => $line[5], 
             6 => $line[6], 
             7 => $state, 
             8 => $ind);

       
#       $self->{'x509clist'}->set_text($row, 7, $state);
#       if($state eq _("VALID")) {
#          $self->{'x509clist'}->set_cell_style($row, 7, $self->{'stylegreen'});
#       } else {
#          $self->{'x509clist'}->set_cell_style($row, 7, $self->{'stylered'});
#       }
#       $self->{'x509clist'}->set_text($row, 8, $ind);
        $ind++;
     }
}

sub update_info {
    my ($self)=@_;

    my ($title, $parsed, $dn);

    $dn = selection_dn($self);

    if (defined $dn) {
       $dn = HELPERS::enc_base64($dn);

       if ($self->{'mode'} eq 'cert') { 
          $parsed = $self->{'main'}->{'CERT'}->parse_cert($self->{'main'},
                $dn, $false);
          $title  = _("Certificate Information");
       } else { 
          $parsed = $self->{'main'}->{'REQ'}->parse_req($self->{'main'}, $dn,
                $false);
          $title = _("Request Information");
       }

       defined($parsed) || 
          GUI::HELPERS::print_error(_("Can't read file"));

       if(not defined($self->{'infobox'})) { 
          $self->{'infobox'} = Gtk2::VBox->new();
       }

       # printf STDERR "DEBUG: Infowin: $self->{'infowin'}, infobox: $self->{'infobox'}\n";
       $self->{'infowin'}->display($self->{'infobox'}, $parsed,
             $self->{'mode'}, $title);

    } else {
    # nothing selected
       $self->{'infowin'}->hide();
    }
}

#
# add infobox to the browser window
#
sub add_info {
  my $self = shift;

  my ($row, $index, $parsed, $title, $status, $list, $dn);

  if ((defined $self->{'infowin'}) && ($self->{'infowin'} ne "")) { 
     $self->{'infowin'}->hide();
  } else { 
     $self->{'infowin'} = GUI::X509_infobox->new();
  }

  # printf STDERR "Infowin: $self->{'infowin'}\n";
  # printf STDERR "x509clist: $self->{'x509clist'}\n";

  $row = $self->{'x509clist'}->get_selection->get_selected();

  if(defined($row)) { 
     if ($self->{'mode'} eq 'cert') { 
        $index = ($self->{'x509store'}->get($row))[8];
        $list  = $self->{'main'}->{'CERT'}->{'certlist'};
     } else { 
        $index = ($self->{'x509store'}->get($row))[7];
        $list  = $self->{'main'}->{'REQ'}->{'reqlist'};
     }
  }

  if (defined $index) {
    ($dn, $status) = split(/\%/, $list->[$index]);
    $dn = HELPERS::enc_base64($dn);

    if ($self->{'mode'} eq 'cert') { 
       $parsed = $self->{'main'}->{'CERT'}->parse_cert($self->{'main'}, $dn,
             $false);
       $title="Certificate Information";
    } else {
      $parsed = $self->{'main'}->{'REQ'}->parse_req($self->{'main'}, $dn,
            $false);
      $title="Request Information";
    }

    defined($parsed) || GUI::HELPERS::print_error(_("Can't read file"));

    # printf STDERR "Infowin: $self->{'infowin'}\n";
    $self->{'infobox'} = Gtk2::VBox->new();
    $self->{'x509pane'}->pack2($self->{'infobox'}, 1, 1);
    $self->{'infowin'}->display($self->{'infobox'}, $parsed, $self->{'mode'},
          $title);
  }
}

sub hide {
  my ($self) = @_;

  $self->{'window'}->hide();
  $self->{'dialog_shown'} = $false;
}

sub destroy {
  my ($self) = @_;

  $self->{'window'}->destroy();
  $self->{'dialog_shown'} = $false;
}

#
# signal handler for selected list items
# (updates the X509_infobox window) 
# XXX why is that function needed??
#
sub _fill_info {
   my ($self) = @_;

   # print STDERR "DEBUG: fill_info: @_\n";
   update_info($self) if (defined $self->{'infowin'});
}

sub selection_fname {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $filename, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if ($self->{'mode'} eq 'req') {
     $index = ($self->{'x509store'}->get($row))[7];
     $list  = $self->{'main'}->{'REQ'}->{'reqlist'};
  } elsif ($self->{'mode'} eq 'cert') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'CERT'}->{'certlist'};
  } elsif ($self->{'mode'} eq 'key') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'KEY'}->{'certlist'};
  } else {
     GUI::HELPERS::print_error( 
           _("Invalid browser mode for selection_fname():"." "
              .$self->{'mode'}));
  }


  if (defined $index) {
     ($dn, $status) = split(/\%/, $list->[$index]);
     $filename= HELPERS::enc_base64($dn);
     $filename=$self->{'actdir'}."/$filename".".pem";
  } else {
     $filename = undef;
  }

  return($filename);
}

sub selection_dn {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if ($self->{'mode'} eq 'req') { 
     $index = ($self->{'x509store'}->get($row))[7];
     $list  = $self->{'main'}->{'REQ'}->{'reqlist'};
  } elsif ($self->{'mode'} eq 'cert') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'CERT'}->{'certlist'};
  } elsif ($self->{'mode'} eq 'key') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'KEY'}->{'keylist'};
  } else {
     GUI::HELPERS::print_error( 
           _("Invalid browser mode for selection_dn():"." "
              .$self->{'mode'}));
  }

  if (defined $index) { 
     ($dn, $status) = split(/\%/, $list->[$index]);
  } else {
     $dn = undef;
  }

  return($dn);
}

sub selection_cadir {
  my $self = shift;

  my $dir;

  $dir = $self->{'actdir'};
  # cut off the last directory name to provide the ca-directory
  $dir =~ s/\/certs|\/req|\/keys$//;
  return($dir);
}


sub selection_caname {
  my $self = shift;

  my ($selected, $caname);

  $caname   = $self->{'actca'};
  return($caname);
}

sub selection_cn {
  my $self = shift;

  my ($selected, $row, $index, $cn);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if (($self->{'mode'} eq 'req') || 
      ($self->{'mode'} eq 'cert')|| 
      ($self->{'mode'} eq 'key')) {
     $cn = ($self->{'x509store'}->get($row))[0];
  } else {
     GUI::HELPERS::print_error( 
           _("Invalid browser mode for selection_cn():"." "
              .$self->{'mode'}));
  }

  return($cn);
}

sub selection_email {
  my $self = shift;

  my ($selected, $row, $index, $email);

  $row = $self->{'x509clist'}->get_selection->get_selected();
  return undef if (not defined $row);

  if (($self->{'mode'} eq 'req') || 
      ($self->{'mode'} eq 'cert') ||
      ($self->{'mode'} eq 'key')) {
     $email = ($self->{'x509store'}->get($row))[1];
  } else {
     GUI::HELPERS::print_error(
           _("Invalid browser mode for selection_cn():"." "
              .$self->{'mode'}));
  }

  return($email);
}

sub selection_status {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();
  
  return undef if (not defined $row);

  if ($self->{'mode'} eq 'cert') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'CERT'}->{'certlist'};
  } else {
     GUI::HELPERS::print_error( 
           _("Invalid browser mode for selection_status():"." "
              .$self->{'mode'}));
  }

  if (defined $index) { 
     ($dn, $status) = split(/\%/, $list->[$index]);
  } else {
     $status = undef;
  }

  return($status);
}

sub selection_type {
  my $self = shift;

  my ($selected, $row, $index, $dn, $type, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();
  
  return undef if (not defined $row);

  if ($self->{'mode'} eq 'key') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'KEY'}->{'keylist'};
  } else {
     GUI::HELPERS::print_error( 
           _("Invalid browser mode for selection_type():"." "
              .$self->{'mode'}));
  }

  if (defined $index) { 
     ($dn, $type) = split(/\%/, $list->[$index]);
  } else {
     $type = undef;
  }

  return($type);
}


sub ok_function {
  my ($self) = @_;

  # is there a user defined ok_function?
  if (defined $self->{'User_OK_function'}) {
    $self->{'User_OK_function'}($self, selection_fname($self));
    }
  # otherwise do default
  else {
    printf STDOUT "%s\n", selection_fname($self);
    $self->hide();
    }
  return $true;
  
}

sub cancel_function {
  my ($self) = @_;

  # is there a user defined ok_function?
  if (defined $self->{'User_CANCEL_function'}) {
    $self->{'User_CANCEL_function'}($self, get_listselect($self));
    }
  # otherwise do default
  else {
    $self->{'window'}->hide();
    $self->{'dialog_shown'} = $false;
    }
  return $true;
}



#
# sort the table by the clicked column
#
sub _sort_clist {
   my ($clist, $col) = @_;

   $clist->set_sort_column($col);
   $clist->sort();

   return(1);
}


#
# called on mouseclick in certlist
#
sub _show_cert_menu {
   my ($clist, $self, $event) = @_;

   if ((defined($event->{'type'})) &&
         $event->{'button'} == 3) {  
      $self->{'certmenu'}->popup(    
            undef,
            undef,
            0,
            $event->{'button'},
            undef);

      return(1);
   }

   return(0);
}

$true;

__END__

=head1 NAME

GUI::X509_browser - Perl-Gtk2 browser for X.509 certificates and requests

=head1 SYNOPSIS

    use X509_browser;

    $browser=X509_browser->new($mode);
    $browser->create_window($title, $oktext, $canceltext,
                            \&okayfunction, \&cancelfunction);
    $browser->add_ca_select($cadir, @calist, $active-ca);
    $browser->add_list($active-ca, $X509dir, $crlfile, $indexfile);
    $browser->add_info();
    my $selection = $browser->selection_fname();
    $browser->hide();

=head1 DESCRIPTION

This displays a browser for X.509v3 certificates or certification
requests (CSR) from a CA managed by TinyCA2 (or some similar
structure).

Creation of an X509_browser is done by calling B<new()>,
the argument has to be 'cert' or 'req' to display certificates
or requests.

A window can be created for this purpose using
B<create_window($title, $oktext, $canceltext, \&okfunction, \&cancelfunction)>,
all arguments are optional.

=over 1

=item $title:

the existing Gtk2::VBox inside which the info will be
displayed.

=item $oktext:

The text to be displayed on the OK button of the dialog.

=item $canceltext:

The text to be displayed on the CANCEL button of the dialog.

=item \&okfunction:

Reference to a function that is executed on click on OK button.
This function should fetch the selected result (using
B<selection_fname()>) and also close the dialog using B<hide()>.

=item \&cancelfunction:

Reference to a function that is executed on click on CANCEL button.
This function should also close the dialog using B<hide()>.

=back

Further functions to get information about the selected item
exist, these are <B>selection_dn()</B>, <B>selection_status()</B>,
<B>selection_cadir()</B> and <B>selection_caname()</B>.

An existing infobox that already displays the content
of some directory can be modified by calling
<B>update()</B> with the same arguments that add_list().

An existing infobox is destroyed by calling B<destroy()>.

=cut
