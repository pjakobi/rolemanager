package tsn.iam.roles;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class SpifDescriptor {
	private ASN1ObjectIdentifier oid;
	private String name;
	private String file;
	
	public SpifDescriptor( ASN1ObjectIdentifier oid, String name, String file ) {
		this.oid = oid;
		this.name = name;
		this.file = file;
	} // SpifDescriptor
	
	public Boolean equals (ASN1ObjectIdentifier oid) { 
		if (oid.equals(this.oid)) return true;
		return false;
	}
	
	
	public ASN1ObjectIdentifier getOid() { return oid; }
	public String getName () { return name; }
	public String getFile () { return file; }
} // class SpifDescriptor
