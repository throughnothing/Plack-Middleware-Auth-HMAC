package Plack::Middleware::Auth::HMAC;
use parent qw( Plack::Middleware );
use Crypt::Mac::HMAC qw(hmac_b64);
use Plack::Request;

# ABSTRACT: HMAC Authorization Middleware

# The check_nonce method checks the nonce for validity
# The get_secret method should return the 'secret' key for the
#     given id/key of the client.  It should return undef or die
#     if the id/key sent by the client is invalid
# The hash is the type of hash to apply with the HMAC, defaults to SHA1
use Plack::Util::Accessor qw(check_nonce get_secret hash serialize_req error);

sub prepare_app {
    my ($self) = @_;
    die 'get_secret sub is required' unless ref $self->get_secret eq 'CODE';
    die 'check_nonce sub is required' unless ref $self->check_nonce eq 'CODE';
	die 'serialize_req sub is required' unless ref $self->serialize_req eq 'CODE';
    $self->hash( $self->hash || 'SHA1' );
	$self->error( $self->error || sub { shift; die @_ } );
}
 
sub call {
    my($self, $env) = @_;
    my $req   = Plack::Request->new($env);
    my $auth  = $req->header('Authorization');
    
    $self->e('Not HMAC Authorization Header') unless $auth =~ /^HMAC (.*)$/i;
    my ($id,$nonce,$sig) = split /:/, $1;
    $self->e('Invalid HMAC Authorization Header') unless $id && $sig && $nonce;

    # Check that the nonce is valid
    $self->e('Invalid Nonce') unless $self->check_nonce->($nonce);

	my $secret = $self->get_secret->($id);
	$self->e('Invalid ID') unless $secret;
    my $computed_sig = hmac_b64( $self->hash, $secret,
		$self->serialize_req->($req, $nonce, $id));
    $self->e('Invalid HMAC Signature') unless $sig eq $computed_sig;
    return $self->app->($env);
}

sub e { shift->error->( @_ ) }

1;
