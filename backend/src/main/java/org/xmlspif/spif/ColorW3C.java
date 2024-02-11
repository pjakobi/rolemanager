//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2022.05.01 at 12:18:02 PM CEST 
//


package org.xmlspif.spif;

import jakarta.xml.bind.annotation.XmlEnum;
import jakarta.xml.bind.annotation.XmlEnumValue;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for colorW3C.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="colorW3C">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="aqua"/>
 *     &lt;enumeration value="black"/>
 *     &lt;enumeration value="blue"/>
 *     &lt;enumeration value="fuschia"/>
 *     &lt;enumeration value="gray"/>
 *     &lt;enumeration value="green"/>
 *     &lt;enumeration value="lime"/>
 *     &lt;enumeration value="maroon"/>
 *     &lt;enumeration value="navy"/>
 *     &lt;enumeration value="olive"/>
 *     &lt;enumeration value="purple"/>
 *     &lt;enumeration value="red"/>
 *     &lt;enumeration value="silver"/>
 *     &lt;enumeration value="teal"/>
 *     &lt;enumeration value="white"/>
 *     &lt;enumeration value="yellow"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "colorW3C")
@XmlEnum
public enum ColorW3C {

    @XmlEnumValue("aqua")
    AQUA("aqua"),
    @XmlEnumValue("black")
    BLACK("black"),
    @XmlEnumValue("blue")
    BLUE("blue"),
    @XmlEnumValue("fuschia")
    FUSCHIA("fuschia"),
    @XmlEnumValue("gray")
    GRAY("gray"),
    @XmlEnumValue("green")
    GREEN("green"),
    @XmlEnumValue("lime")
    LIME("lime"),
    @XmlEnumValue("maroon")
    MAROON("maroon"),
    @XmlEnumValue("navy")
    NAVY("navy"),
    @XmlEnumValue("olive")
    OLIVE("olive"),
    @XmlEnumValue("purple")
    PURPLE("purple"),
    @XmlEnumValue("red")
    RED("red"),
    @XmlEnumValue("silver")
    SILVER("silver"),
    @XmlEnumValue("teal")
    TEAL("teal"),
    @XmlEnumValue("white")
    WHITE("white"),
    @XmlEnumValue("yellow")
    YELLOW("yellow");
    private final String value;

    ColorW3C(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ColorW3C fromValue(String v) {
        for (ColorW3C c: ColorW3C.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
