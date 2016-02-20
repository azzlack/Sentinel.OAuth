namespace Sentinel.Sample.ModelBinders
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Web.Mvc;

    public class AliasModelBinder : DefaultModelBinder
    {
        /// <summary>
        /// Returns the properties of the model by using the specified controller context and binding context.
        /// </summary>
        /// <returns>
        /// A collection of property descriptors.
        /// </returns>
        /// <param name="controllerContext">The context within which the controller operates. The context information includes the controller, HTTP content, request context, and route data.</param><param name="bindingContext">The context within which the model is bound. The context includes information such as the model object, model name, model type, property filter, and value provider.</param>
        protected override PropertyDescriptorCollection GetModelProperties(ControllerContext controllerContext, ModelBindingContext bindingContext)
        {
            var toReturn = base.GetModelProperties(controllerContext, bindingContext);

            var additional = new List<PropertyDescriptor>();

            foreach (var p in this.GetTypeDescriptor(controllerContext, bindingContext).GetProperties().Cast<PropertyDescriptor>())
            {
                foreach (var attr in p.Attributes.OfType<BindAliasAttribute>())
                {
                    additional.Add(new BindAliasAttribute.AliasedPropertyDescriptor(attr.Alias, p));

                    if (bindingContext.PropertyMetadata.ContainsKey(p.Name) && !bindingContext.PropertyMetadata.ContainsKey(attr.Alias))
                    {
                        bindingContext.PropertyMetadata.Add(attr.Alias, bindingContext.PropertyMetadata[p.Name]);
                    }
                }
            }

            return new PropertyDescriptorCollection(toReturn.Cast<PropertyDescriptor>().Concat(additional).ToArray());
        }
    }

    [AttributeUsage(AttributeTargets.Property, AllowMultiple = true)]
    public class BindAliasAttribute : Attribute
    {
        public BindAliasAttribute(string alias)
        {
            this.Alias = alias;
        }

        public string Alias { get; private set; }

        public override object TypeId
        {
            get { return this.Alias; }
        }

        internal sealed class AliasedPropertyDescriptor : PropertyDescriptor
        {
            public PropertyDescriptor Inner { get; private set; }

            public AliasedPropertyDescriptor(string alias, PropertyDescriptor inner)
                : base(alias, null)
            {
                this.Inner = inner;
            }

            public override bool CanResetValue(object component)
            {
                return this.Inner.CanResetValue(component);
            }

            public override Type ComponentType
            {
                get { return this.Inner.ComponentType; }
            }

            public override object GetValue(object component)
            {
                return this.Inner.GetValue(component);
            }

            public override bool IsReadOnly
            {
                get { return this.Inner.IsReadOnly; }
            }

            public override Type PropertyType
            {
                get { return this.Inner.PropertyType; }
            }

            public override void ResetValue(object component)
            {
                this.Inner.ResetValue(component);
            }

            public override void SetValue(object component, object value)
            {
                this.Inner.SetValue(component, value);
            }

            public override bool ShouldSerializeValue(object component)
            {
                return this.Inner.ShouldSerializeValue(component);
            }
        }
    }
}