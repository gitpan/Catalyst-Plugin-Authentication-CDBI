package Catalyst::Plugin::Authentication::CDBI;

use strict;
use NEXT;

our $VERSION = '0.01';

=head1 NAME

Catalyst::Plugin::Authentication::CDBI - CDBI Authentication for Catalyst

=head1 SYNOPSIS

    use Catalyst 'Authentication::CDBI';
    __PACKAGE__->config->{authentication} = (
        user_class           => 'PetStore::Model::CDBI::Customer',
        user_field           => 'email',
        role_class           => 'PetStore::Model::CDBI::Role',
        user_role_class      => 'PetStore::Model::CDBI::CustomerRole',
        user_role_user_field => 'customer'
    );
    $c->login( $user, $password );
    $c->logout;
    $c->session_login( $user, $password );
    $c->session_logout;

    CREATE TABLE customer (
        id INTEGER PRIMARY KEY,
        email TEXT,
        password TEXT
    );

    CREATE TABLE role (
        id INTEGER PRIMARY KEY,
        role TEXT
    );

    CREATE TABLE customer_role (
        id INTEGER PRIMARY KEY,
        customer INTEGER REFERENCES customer,
        role INTEGER REFERENCES role
    );

=head1 DESCRIPTION

Note that this plugin requires a session plugin like
C<Catalyst::Plugin::Session::FastMmap>.

=head2 EXTENDED METHODS

=head3 prepare_action

=head3 setup

=head2 OVERLOADED METHODS

=head3 process_roles

=head2 METHODS

=head3 login

Login.

    $c->login( $user, $password );

=cut

sub login {
    my ( $c, $user, $password ) = @_;
    return 1 if $c->request->user;
    my $user_class     = $c->config->{authentication}->{user_class};
    my $user_field     = $c->config->{authentication}->{user_field} || 'user';
    my $password_field = $c->config->{authentication}->{password_field}
      || 'password';
    if (
        $user_class->search(
            { $user_field => $user, $password_field => $password }
        )
      )
    {
        $c->request->{user} = $user;
        return 1;
    }
    return 0;
}

=head3 logout

Logout.

=cut

sub logout {
    my $c = shift;
    $c->request->user(undef);
}

sub prepare_action {
    my $c = shift;
    $c->NEXT::prepare_action(@_);
    $c->request->{user} = $c->session->{user};
}

sub process_roles {
    my ( $c, $roles ) = @_;
    my $user_class      = $c->config->{authentication}->{user_class};
    my $user_field      = $c->config->{authentication}->{user_field} || 'user';
    my $role_class      = $c->config->{authentication}->{role_class};
    my $role_field      = $c->config->{authentication}->{role_field} || 'role';
    my $user_role_class = $c->config->{authentication}->{user_role_class};
    my $user_role_user_field =
      $c->config->{authentication}->{user_role_user_field} || 'user';
    my $user_role_role_field =
      $c->config->{authentication}->{user_role_role_field} || 'role';

    if ( my $user =
        $user_class->search( { $user_field => $c->request->user } )->first )
    {
        for my $role (@$roles) {
            if ( my $role =
                $role_class->search( { $role_field => $role } )->first )
            {
                return 0
                  unless $user_role_class->search(
                    {
                        $user_role_user_field => $user->id,
                        $user_role_role_field => $role->id
                    }
                  );
            }
            else { return 0 }
        }
    }
    else { return 0 }
    return 1;
}

=head3 session_login

Login.

    $c->session_login( $user, $password );

=cut

sub session_login {
    my ( $c, $user, $password ) = @_;
    return 0 unless $c->login( $user, $password );
    $c->session->{user} = $user;
    return 1;
}

=head3 session_logout

Session logout.

=cut

sub session_logout {
    my $c = shift;
    $c->logout;
    $c->session->{user} = undef;
}

sub setup {
    my $c    = shift;
    my $conf = $c->config->{authentication};
    $conf = ref $conf eq 'ARRAY' ? {@$conf} : $conf;
    $c->config->{authentication} = $conf;
    return $c->NEXT::setup(@_);
}

=head1 SEE ALSO

L<Catalyst>.

=head1 AUTHOR

Sebastian Riedel, C<sri@cpan.org>

=head1 COPYRIGHT

This program is free software, you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

1;
