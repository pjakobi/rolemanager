//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2022.05.01 at 12:18:02 PM CEST 
//


package org.xmlspif.spif;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for securityCategoryTagSets complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="securityCategoryTagSets">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.xmlspif.org/spif}securityCategoryTagSet" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "securityCategoryTagSets", propOrder = {
    "securityCategoryTagSet"
})
public class SecurityCategoryTagSets {

    @XmlElement(required = true)
    protected List<SecurityCategoryTagSet> securityCategoryTagSet;

    /**
     * Gets the value of the securityCategoryTagSet property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the securityCategoryTagSet property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSecurityCategoryTagSet().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link SecurityCategoryTagSet }
     * 
     * 
     */
    public List<SecurityCategoryTagSet> getSecurityCategoryTagSet() {
        if (securityCategoryTagSet == null) {
            securityCategoryTagSet = new ArrayList<SecurityCategoryTagSet>();
        }
        return this.securityCategoryTagSet;
    }

}
