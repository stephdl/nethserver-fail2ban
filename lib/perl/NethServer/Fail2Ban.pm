#
# Copyright (C) 2019 Nethesis S.r.l.
# http://www.nethesis.it - nethserver@nethesis.it
#
# This script is part of NethServer.
#
# NethServer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License,
# or any later version.
#
# NethServer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NethServer.  If not, see COPYING.
#
package NethServer::Fail2Ban;

use strict;
use esmith::ConfigDB;

=head1 NAME
NethServer::Fail2ban -- utility functions for fail2ban
=cut

=head1 DESCRIPTION
TODO
=cut

=head1 USAGE
Usage example:
  use NethServer::Fail2ban;
  ...
=cut

=head1 FUNCTIONS
=head2 listJails
Return the list of jails
=cut

sub listAllJails {
    my @jails;
    push(@jails, listApacheErrorJails());
    push(@jails, listApacheAccessJails());
    push(@jails, listSSHJails());
    push(@jails, listAsteriskJails());
    push(@jails, listDovecotJails());
    push(@jails, listHttpdAdminJails());
    push(@jails, listEjabberAuthJails());
    push(@jails, listMysqldAuthJails());
    push(@jails, listNextcloudAuthJails());
    push(@jails, listOwnCloudAuthJails());
    push(@jails, listNginxHttpAuthJails());
    # ... other jails

    return @jails;
}
sub listNginxHttpAuthJails {
  my @jails;
  my $db = esmith::ConfigDB->open_ro();
  my $nginx = $nginx{status} || 'disabled';

  if (-f '/var/log/nginx/error.log') {
      foreach(qw(HttpAuth BotSearch)) {
          my $status = $db->get_prop('fail2ban', 'Nginx'.$_.'_status') || 'true';
          if (($status eq 'true') && ($nginx eq 'enabled')) {
              $_ =~ s/HttpAuth/http-auth/;
              push(@jails, 'nginx-'.lc $_);
          }
      }
  }
  return @jails;
}

sub listOwncloudAuthJails() {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $status = $db->get_prop('fail2ban', 'Owncloud_status') || 'true';

    if (( -f '/var/www/html/owncloud/data/owncloud.log') &&
      ($status eq 'true') {
        push(@jails, 'owncloud-auth');
    }
    return @jails;
}

sub listNextcloudAuthJails() {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $status = $db->get_prop('fail2ban', 'Nextcloud_status') || 'true';

    if (( -f '/var/lib/nethserver/nextcloud/nextcloud.log') &&
      ($status eq 'true') {
        push(@jails, 'nextcloud-auth');
    }
    return @jails;
}

sub listMysqldAuthJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $mysqld = $db->get_prop('mysqld', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'MysqldAuth_status') || 'true';

    if (( -f '/var/log/mariadb/mariadb.log') &&
      ($status eq 'true') &&
      ($mysqld eq 'enabled')) {
        push(@jails, 'mysqld-auth');
    }
    return @jails;
}

sub listEjabberAuthJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $ejabberd = $db->get_prop('ejabberd', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'EjabberAuth_status') || 'true';

    if (( -f '/var/log/ejabberd/ejabberd.log') &&
      ($status eq 'true') &&
      ($ejabberd eq 'enabled')) {
        push(@jails, 'ejabberd-auth');
    }
    return @jails;
}

sub listHttpdAdminJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $httpd_admin = $db->get_prop('httpd-admin', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'HttpdAdmin_status') || 'true';

    if (( -f '/var/log/httpd-admin/access_log') &&
      ($status eq 'true') &&
      ($httpd_admin eq 'enabled')) {
        push(@jails, 'httpd-admin');
    }
    return @jails;
}

sub listDovecotJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $dovecot = $db->get_prop('dovecot', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'Dovecot_status') || 'true';

    if ( -f '/var/log/imap') {
        foreach (qw( dovecot dovecot-nethserver )) {
            if (($status eq 'true') && ($dovecot eq 'enabled')) {
                push(@jails, $_);
            }
        }
    }
    return @jails;
}

sub listAsteriskJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $asterisk = $db->get_prop('asterisk', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'AsteriskAuth_status') || 'true';

    if ( -f '/var/log/asterisk/full') {
        foreach (qw( asterisk asterisk_nethserver )) {
            if (($status eq 'true') && ($asterisk eq 'enabled')){
                push(@jails, $_);
            }
        }
    }
    return @jails;
}

sub listSSHJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $sshd = $db->get_prop('sshd', 'status') || 'enabled';
    my $status = $db->get_prop('fail2ban', 'Sshd_status') || 'true';

    if (( -f '/var/log/secure') &&
      ($status eq 'true') &&
      ($sshd eq 'enabled')) {
        push(@jails, 'sshd');
    }
    return @jails;
}

sub listApacheErrorJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $httpd = $db->get_prop('httpd', 'status') || 'enabled';

    if ( -f '/var/log/httpd/error_log') {
        foreach (qw(Auth Noscript Overflows Nohome Botsearch Modsecurity Shellshock Scan )) {
            my $status = $db->get_prop('fail2ban', 'Apache'.$_.'_status') || 'true';
            if (($status eq 'true') && ($httpd eq 'enabled')) {
                push(@jails, 'apache-'.lc $_);
            }
        }
    }
    return @jails;
}

sub listApacheAccessJails {
    my @jails;
    my $db = esmith::ConfigDB->open_ro();
    my $httpd = $db->get_prop('httpd', 'status') || 'enabled';

    if (-f '/var/log/httpd/access_log') {
        foreach(qw(Fakegooglebot Badbots)) {
            my $status = $db->get_prop('fail2ban', 'Apache'.$_.'_status') || 'true';
            if (($status eq 'true') && ($httpd eq 'enabled')) {
                push(@jails, 'apache-'.lc $_);
            }
        }
        my $phpmyadmin = $db->get_prop('fail2ban', 'ApachePhpMyAdmin_status') || 'true';
        if (($phpmyadmin eq 'true') && ($httpd eq 'enabled')) {
            push(@jails, 'phpmyadmin');
        }

    }
    return @jails;
}


1;
