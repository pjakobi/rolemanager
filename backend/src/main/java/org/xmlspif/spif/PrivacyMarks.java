//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2022.05.01 at 12:18:02 PM CEST 
//


package org.xmlspif.spif;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for privacyMarks complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="privacyMarks">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.xmlspif.org/spif}privacyMark" maxOccurs="unbounded"/>
 *         &lt;element ref="{http://www.xmlspif.org/spif}markingData" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://www.xmlspif.org/spif}markingQualifier" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="maxSelection" type="{http://www.xmlspif.org/spif}selection" default="unbounded" />
 *       &lt;attribute name="minSelection" type="{http://www.xmlspif.org/spif}selection" default="unbounded" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "privacyMarks", propOrder = {
    "privacyMark",
    "markingData",
    "markingQualifier"
})
public class PrivacyMarks {

    @XmlElement(required = true)
    protected List<PrivacyMark> privacyMark;
    protected List<MarkingData> markingData;
    protected List<MarkingQualifier> markingQualifier;
    @XmlAttribute(name = "maxSelection")
    protected String maxSelection;
    @XmlAttribute(name = "minSelection")
    protected String minSelection;

    /**
     * Gets the value of the privacyMark property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the privacyMark property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPrivacyMark().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PrivacyMark }
     * 
     * 
     */
    public List<PrivacyMark> getPrivacyMark() {
        if (privacyMark == null) {
            privacyMark = new ArrayList<PrivacyMark>();
        }
        return this.privacyMark;
    }

    /**
     * Gets the value of the markingData property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the markingData property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getMarkingData().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link MarkingData }
     * 
     * 
     */
    public List<MarkingData> getMarkingData() {
        if (markingData == null) {
            markingData = new ArrayList<MarkingData>();
        }
        return this.markingData;
    }

    /**
     * Gets the value of the markingQualifier property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the markingQualifier property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getMarkingQualifier().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link MarkingQualifier }
     * 
     * 
     */
    public List<MarkingQualifier> getMarkingQualifier() {
        if (markingQualifier == null) {
            markingQualifier = new ArrayList<MarkingQualifier>();
        }
        return this.markingQualifier;
    }

    /**
     * Gets the value of the maxSelection property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getMaxSelection() {
        if (maxSelection == null) {
            return "unbounded";
        } else {
            return maxSelection;
        }
    }

    /**
     * Sets the value of the maxSelection property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setMaxSelection(String value) {
        this.maxSelection = value;
    }

    /**
     * Gets the value of the minSelection property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getMinSelection() {
        if (minSelection == null) {
            return "unbounded";
        } else {
            return minSelection;
        }
    }

    /**
     * Sets the value of the minSelection property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setMinSelection(String value) {
        this.minSelection = value;
    }

}
