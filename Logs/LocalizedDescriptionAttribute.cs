using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;

namespace auth.Logs
{
    /// <summary>
    /// Attribute that supports localization.
    /// </summary>
    /// <seealso cref="System.ComponentModel.DescriptionAttribute" />
    public class LocalizedDescriptionAttribute : DescriptionAttribute
    {
        /// <summary>
        /// The localized string property.
        /// </summary>
        private readonly PropertyInfo _localizedStringProperty;

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalizedDescriptionAttribute"/> class.
        /// </summary>
        /// <param name="key">The key of the localization resource.</param>
        /// <param name="resources">The type of the resource dictionary containing the key.</param>
        public LocalizedDescriptionAttribute(string key, Type resources)
            : base(key)
        {
            _localizedStringProperty = resources.GetProperty(key, BindingFlags.Static | BindingFlags.Public);
        }

        /// <summary>
        /// Gets the description stored in this attribute.
        /// </summary>
        public override string Description => _localizedStringProperty?.GetValue(_localizedStringProperty.DeclaringType, null)?.ToString() ?? base.Description;

        /// <summary>
        /// Gets the enum description.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string GetEnumDescription(Enum value)
        {
            if (value.GetType().GetCustomAttributes<FlagsAttribute>().Any())
            {
                var values = new List<Enum>();
                // On doit sauter le test de 0 dans le cas flag, car tous les flags ont la valeur 0, qui doit être réservée à l'absence de valeur dans les flags
                var zero = Enum.ToObject(value.GetType(), 0);
                return string.Join(" | ", Enum.GetValues(value.GetType()).Cast<Enum>()
                                                                       .Where(v => !Equals(zero, v) && value.HasFlag(v))
                                                                       .Select(v => GetSingleEnumDescription(v)));
            }
            return GetSingleEnumDescription(value);
        }

        /// <summary>
        /// Gets the single enum description.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        private static string GetSingleEnumDescription(Enum value)
        {
            var fieldInfo = value.GetType().GetField(value.ToString());
            var attributesArray = fieldInfo.GetCustomAttributes(false);
            return attributesArray.OfType<LocalizedDescriptionAttribute>().FirstOrDefault()?.Description ?? value.ToString();
        }
    }
}
