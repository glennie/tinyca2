# Copyright (c) Olaf Gellert <og@pre-secure.de> and
#               Stephan Martin <sm@sm-zone.net>
#
# $Id: X509_infobox.pm,v 1.7 2006/06/28 21:50:42 sm Exp $
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
package GUI::X509_infobox;

use HELPERS;
use GUI::HELPERS;
use GUI::WORDS;

use POSIX;

my $version = "0.1";
my $true = 1;
my $false = undef;

sub new {
   my $that = shift;
   my $self = {};

   my $class = ref($that) || $that;

   $self->{'init'} = shift;

   bless($self, $class);

   $self;
}


sub display {
  my ($self, $parent, $parsed, $mode, $title) = @_;

  my ($bottombox, $textbox, $lefttable, $righttable, $leftbox, $rightbox,
        @fields, $scrolled);

  $self->{'root'} = $parent;

  if (defined $self->{'child'}) {
    $self->{'child'}->destroy();
    }

  # if title is given create a surrounding frame with the title
  if (defined $title) {
     $self->{'child'}= Gtk2::Frame->new($title);
     $self->{'x509textbox'}= Gtk2::VBox->new(0,0);
     $self->{'child'}->add($self->{'x509textbox'});
  }
  # otherwise we create the VBox directly inside the root widget
  else {
     $self->{'child'} = Gtk2::VBox->new(0,0);
     $self->{'x509textbox'} = $self->{'child'};  
  }

  # and pack it there  
  $self->{'root'}->pack_start($self->{'child'}, 1, 1, 0);

   if (($mode eq 'cert') || ($mode eq 'cacert')) {
      # fingerprint in the top of certtextbox
      if(defined($self->{'certfingerprintmd5'})) {
         $self->{'certfingerprintmd5'}->destroy();
      } 
      $self->{'certfingerprintmd5'} = GUI::HELPERS::create_label(
            _("Fingerprint (MD5)").": ".$parsed->{'FINGERPRINTMD5'},
            'center', 0, 0);
      $self->{'x509textbox'}->pack_start( $self->{'certfingerprintmd5'}, 
            0, 0, 0);

      if(defined($self->{'certfingerprintsha1'})) {
         $self->{'certfingerprintsha1'}->destroy();
      } 
      $self->{'certfingerprintsha1'} = GUI::HELPERS::create_label(
            _("Fingerprint (SHA1)").": ".$parsed->{'FINGERPRINTSHA1'},
            'center', 0, 0);
      $self->{'x509textbox'}->pack_start($self->{'certfingerprintsha1'}, 
            0, 0, 0);
   }

   if (($mode eq 'cert') || ($mode eq 'cacert')) {
      $bottombox  = 'certbottombox';
      $textbox    = 'x509textbox';
      $lefttable  = 'certlefttable';
      $leftbox    = 'certleftbox';
      $righttable = 'certrighttable';
      $rightbox   = 'certrightbox';
   }else{
      $bottombox  = 'reqbottombox';
      $textbox    = 'x509textbox';
      $lefttable  = 'reqlefttable';
      $leftbox    = 'reqleftbox';
      $righttable = 'reqrighttable';
      $rightbox   = 'reqrightbox';
   }

   # hbox in the bottom
   if(defined($self->{$bottombox})) {
      $self->{$bottombox}->destroy();
   }
   $self->{$bottombox} = Gtk2::HBox->new(1, 0);
   $self->{$textbox}->pack_start($self->{$bottombox}, 1, 1, 5);

   # vbox in the bottom/left
   if(defined($self->{$lefttable})) {
      $self->{$lefttable}->destroy();
   }
   @fields = qw( CN EMAIL O OU L ST C);
   $self->{$lefttable} = _create_detail_table(\@fields, $parsed);

   # the only widget i know to set shadow type :-(
   $scrolled = Gtk2::ScrolledWindow->new();
   $scrolled->set_shadow_type('etched-in');
   $scrolled->set_policy('never', 'never');
   
   $self->{$leftbox} = Gtk2::VBox->new(0, 0);
   $self->{$bottombox}->pack_start($self->{$leftbox}, 1, 1, 0);

   $self->{$leftbox}->pack_start($scrolled, 1, 1, 0);
   $scrolled->add($self->{$lefttable});

   # vbox in the bottom/right
   if(defined($self->{$righttable})) {
      $self->{$righttable}->destroy();
   }
   if ($mode eq "cacert") {
     @fields = qw(SERIAL NOTBEFORE NOTAFTER KEYSIZE PK_ALGORITHM SIG_ALGORITHM
        TYPE);
   } else {
     @fields = qw(STATUS SERIAL NOTBEFORE NOTAFTER KEYSIZE PK_ALGORITHM
        SIG_ALGORITHM TYPE);
   }

   $self->{$righttable} = _create_detail_table(\@fields, $parsed);

   $scrolled = Gtk2::ScrolledWindow->new();
   $scrolled->set_shadow_type('etched-in');
   $scrolled->set_policy('never', 'never');

   $self->{$rightbox} = Gtk2::VBox->new(0, 0);
   $self->{$bottombox}->pack_start($self->{$rightbox}, 1, 1, 0);

   $self->{$rightbox}->pack_start($scrolled, 1, 1, 0);
   $scrolled->add($self->{$righttable});

   $self->{$textbox}->show_all();

   $parent->show_all();
}

sub hide {
  my $self = shift;

  if (defined $self->{'child'}) {
    $self->{'child'}->destroy();
    undef $self->{'child'};
    }
}

#
# create standard table with details (cert/req)
#
sub _create_detail_table {
   my ($fields, $parsed) = @_;

   my ($list, $store, $rows, $words, @l, $iter, $column, $renderer);

   $words = GUI::WORDS->new();

   $store = Gtk2::ListStore->new('Glib::String', 'Glib::String');
   $list  = Gtk2::TreeView->new_with_model($store);
   $list->set_headers_visible(0);
   $list->get_selection->set_mode('none');

   $renderer = Gtk2::CellRendererText->new();
   $column = Gtk2::TreeViewColumn->new_with_attributes(
         '', $renderer, 'text' => 0);
   $list->append_column($column);

   $renderer = Gtk2::CellRendererText->new();
   $column = Gtk2::TreeViewColumn->new_with_attributes(
         '', $renderer, 'text' => 1);
   $list->append_column($column);
   

   foreach my $f (@{$fields}) {
      if(defined($parsed->{$f})){
         if(ref($parsed->{$f})) {
            foreach(@{$parsed->{$f}}) {
               $iter = $store->append();
               $store->set($iter, 0 => $words->{$f}, 1 => $_);
               # print STDERR "DEBUG: add line: @l\n";
               
            }
         }else{
            # print STDERR "DEBUG: add line: @l\n";
            $iter = $store->append();
            $store->set($iter, 0 => $words->{$f}, 1 => $parsed->{$f});
         }
      }
   }

   return($list);
}


1;


__END__

=head1 NAME

GUI::X509_infobox - show X.509 certificates and requests in a Gtk2::VBox

=head1 SYNOPSIS

    use X509_infobox;

    $infobox=X509_infobox->new();
    $infobox->update($parent,$parsed,$mode,$title);
    $infobox->update($parent,$parsed,$mode);
    $infobox->hide();

=head1 DESCRIPTION

This displays the information of an X.509v3 certificate or
certification request (CSR) inside a given Gtk2::VBox.

Creation of an X509_infobox is done by calling B<new()>,
no arguments are required.

The infobox is shown when inserted into an already
existing Gtk2::VBox using the method B<update()>. Arguments
to update are:

=over 1

=item $parent:

the existing Gtk2::VBox inside which the info will be
displayed.

=item $parsed:

a structure returned by OpenSSL::parsecert() or OpenSSL::parsecrl()
containing the required information.

=item $mode:

what type of information is to be displayed. Valid modes
are 'req' (certification request), 'cert' (certificate), 'key' or 'cacert'
(same as certificate but without displaying the validity information
of the cert because this cannot be decided on from the view of the
actual CA).

=item $title:

if specified, a surrounding frame with the given title
is drawn.

=back

An existing infobox is destroyed by calling B<hide()>.

=cut
